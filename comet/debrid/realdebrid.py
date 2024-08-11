import aiohttp
import asyncio

from RTN import parse

from comet.utils.general import is_video
from comet.utils.logger import logger
from comet.utils.models import settings, database


class RealDebrid:
    def __init__(self, session: aiohttp.ClientSession, debrid_api_key: str):
        session.headers["Authorization"] = f"Bearer {debrid_api_key}"
        self.session = session
        self.proxy = None

        self.api_url = "https://api.real-debrid.com/rest/1.0"

    async def check_premium(self):
        try:
            check_premium = await self.session.get(f"{self.api_url}/user")
            check_premium = await check_premium.text()
            if '"type": "premium"' in check_premium:
                return True
        except Exception as e:
            logger.warning(
                f"Exception while checking premium status on Real-Debrid: {e}"
            )

        return False

    async def get_instant(self, chunk: list):
        try:
            response = await self.session.get(
                f"{self.api_url}/torrents/instantAvailability/{'/'.join(chunk)}"
            )
            return await response.json()
        except Exception as e:
            logger.warning(
                f"Exception while checking hash instant availability on Real-Debrid: {e}"
            )

    async def get_files(
        self, torrent_hashes: list, type: str, season: str, episode: str, kitsu: bool
    ):
        chunk_size = 50
        chunks = [
            torrent_hashes[i : i + chunk_size]
            for i in range(0, len(torrent_hashes), chunk_size)
        ]

        tasks = []
        for chunk in chunks:
            tasks.append(self.get_instant(chunk))

        responses = await asyncio.gather(*tasks)

        availability = {}
        for response in responses:
            if response is not None:
                availability.update(response)

        files = {}

        if type == "series":
            for hash, details in availability.items():
                if "rd" not in details:
                    continue

                for variants in details["rd"]:
                    for index, file in variants.items():
                        filename = file["filename"]

                        if not is_video(filename):
                            continue

                        filename_parsed = parse(filename)
                        if episode not in filename_parsed.episode:
                            continue

                        if kitsu:
                            if filename_parsed.season:
                                continue
                        else:
                            if season not in filename_parsed.season:
                                continue

                        files[hash] = {
                            "index": index,
                            "title": filename,
                            "size": file["filesize"],
                            "uncached": False,
                        }

                        break
        else:
            for hash, details in availability.items():
                if "rd" not in details:
                    continue

                for variants in details["rd"]:
                    for index, file in variants.items():
                        filename = file["filename"]

                        if not is_video(filename):
                            continue

                        files[hash] = {
                            "index": index,
                            "title": filename,
                            "size": file["filesize"],
                            "uncached": False,
                        }

                        break

        return files

    async def generate_download_link(self, hash: str, index: str, torrent_link: str = None, possible_torrent_id: str = None):
        try:
            check_blacklisted = await self.session.get("https://real-debrid.com/vpn")
            check_blacklisted = await check_blacklisted.text()
            if (
                "Your ISP or VPN provider IP address is currently blocked on our website"
                in check_blacklisted
            ):
                self.proxy = settings.DEBRID_PROXY_URL
                if not self.proxy:
                    logger.warning(
                        "Real-Debrid blacklisted server's IP. No proxy found."
                    )
                else:
                    logger.warning(
                        f"Real-Debrid blacklisted server's IP. Switching to proxy {self.proxy} for {hash}|{index}"
                    )

            if possible_torrent_id:
                # Use the provided torrentId to prevent caching multiple times
                torrent_id = possible_torrent_id
            elif torrent_link:
                # If torrent_link is provided, handle the torrent file upload
                async with self.session.get(torrent_link) as resp:
                    torrent_data = await resp.read()

                add_torrent = await self.session.put(
                    f"{self.api_url}/torrents/addTorrent",
                    data=torrent_data,
                    proxy=self.proxy,
                )

                add_torrent = await add_torrent.json()

                torrent_id = add_torrent.get("id")
                logger.info(
                    f"Started caching to Real-Debrid this might take some time: {add_torrent}"
                )
                if not torrent_id:
                    raise Exception(f"Failed to get torrent ID from Real-Debrid: {add_torrent}")
            else:
                # Handle magnet link as before
                add_magnet = await self.session.post(
                    f"{self.api_url}/torrents/addMagnet",
                    data={"magnet": f"magnet:?xt=urn:btih:{hash}"},
                    proxy=self.proxy,
                )
                add_magnet = await add_magnet.json()

                torrent_id = add_magnet.get("id")
                if not torrent_id:
                    raise Exception(f"Failed to get magnet ID from Real-Debrid: {add_magnet}")

            # Get torrent information after uploading the torrent or adding the magnet link
            get_magnet_info = await self.session.get(
                f"{self.api_url}/torrents/info/{torrent_id}",
                proxy=self.proxy
            )
            get_magnet_info = await get_magnet_info.json()

            # Reset TorrentId if not found, might happen if user removes it in debridManager
            if get_magnet_info.get("error") == 'unknown_ressource':
                logger.warning(
                    f"Exception while getting file from Real-Debrid, please retry, for {hash}|{index}: {get_magnet_info}"
                )
                await database.execute(
                    "UPDATE uncached_torrents SET torrentId = :torrent_id WHERE hash = :hash",
                    {"torrent_id": "", "hash": hash}
                )
                return None

            # Select the files for downloading
            await self.session.post(
                f"{self.api_url}/torrents/selectFiles/{torrent_id}",
                data={
                    "files": ",".join(
                        str(file["id"])
                        for file in get_magnet_info["files"]
                        if is_video(file["path"])
                    )
                },
                proxy=self.proxy,
            )

            # Get the updated torrent information
            get_magnet_info = await self.session.get(
                f"{self.api_url}/torrents/info/{torrent_id}",
                proxy=self.proxy
            )
            get_magnet_info = await get_magnet_info.json()

            # Update the database with the retrieved torrent_id
            if torrent_link:
                await database.execute(
                    "UPDATE uncached_torrents SET torrentId = :torrent_id WHERE hash = :hash",
                    {"torrent_id": torrent_id, "hash": hash}
                )
            index = int(index)
            realIndex = index
            for file in get_magnet_info["files"]:
                if file["id"] == realIndex:
                    break

                if file["selected"] != 1:
                    index -= 1

            # Skip unrestrict if no links available yet
            if len(get_magnet_info["links"]) == 0:
                logger.info(
                    f"File {hash}|{index} is uncached, please wait until its cached! Status: {get_magnet_info.get('status')} | Progress: {get_magnet_info.get('progress')}"
                )
                return None
            # Get the unrestricted download link
            unrestrict_link = await self.session.post(
                f"{self.api_url}/unrestrict/link",
                data={"link": get_magnet_info["links"][index - 1]},
                proxy=self.proxy,
            )
            unrestrict_link = await unrestrict_link.json()

            return unrestrict_link["download"]
        except Exception as e:
            logger.warning(
                f"Exception while getting download link from Real-Debrid for {hash}|{index}: {e}"
            )
            return None
