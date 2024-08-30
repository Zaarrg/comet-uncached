import aiohttp
import asyncio

from RTN import parse

from comet.utils.general import is_video, check_uncached
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

    async def get_first_files(self, amount: int):
        results = []
        if amount < 0 or amount > 5000:
            logger.warning(f"Max amount exceeded for retrieving torrents explicitly from Real-Debrid")
            return results
        try:
            response = await self.session.get(
                f"{self.api_url}/torrents",
                params={"limit": amount}
            )
            torrents = await response.json()
            for file in torrents:
                results.append(
                    {
                        "Title": file['filename'],
                        "InfoHash": file['hash'],
                        "Size": file["bytes"],
                        "Tracker": "Real-Debrid",
                    }
                )
            logger.info(f"Retrieved {len(results)} torrents explicitly from Real-Debrid")
            return results
        except Exception as e:
            logger.warning(
                f"Exception while getting recent files on Real-Debrid: {e}"
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

    async def add_magnet(self, hash: str):
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
        return torrent_id

    async def add_file(self, torrent_link: str):
        # Download uncached torrent if it has only a link
        async with self.session.get(torrent_link) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to download torrent, please try another one, status code: {resp.status}")
            torrent_data = await resp.read()

        add_torrent = await self.session.put(
            f"{self.api_url}/torrents/addTorrent",
            data=torrent_data,
            proxy=self.proxy,
        )
        add_torrent = await add_torrent.json()

        torrent_id = add_torrent.get("id")
        if not torrent_id:
            raise Exception(f"Failed to get magnet ID from Real-Debrid: {add_torrent}")
        logger.info(
            f"Started caching to Real-Debrid this might take some time: {add_torrent}"
        )
        return torrent_id

    async def get_info(self, torrent_id: str):
        get_magnet_info = await self.session.get(
            f"{self.api_url}/torrents/info/{torrent_id}",
            proxy=self.proxy
        )
        return await get_magnet_info.json()

    async def get_download_link(self, index: int, magnet_info: dict):
        index = int(index)
        realIndex = index
        for file in magnet_info["files"]:
            if file["id"] == realIndex:
                break

            if file["selected"] != 1:
                index -= 1

        # Get the unrestricted download link
        unrestrict_link = await self.session.post(
            f"{self.api_url}/unrestrict/link",
            data={"link": magnet_info["links"][index - 1]},
            proxy=self.proxy,
        )
        unrestrict_link = await unrestrict_link.json()

        return unrestrict_link["download"]

    async def select_files(self, torrent_id: str, magnet_info: dict):
        # Select the files for downloading
        await self.session.post(
            f"{self.api_url}/torrents/selectFiles/{torrent_id}",
            data={
                "files": ",".join(
                    str(file["id"])
                    for file in magnet_info["files"]
                    if is_video(file["path"])
                )
            },
            proxy=self.proxy,
        )

    async def handle_uncached(self, is_uncached: dict, hash: str, index: str):
        torrent_id = is_uncached.get('torrent_id', None)
        has_magnet = is_uncached.get('has_magnet', None)

        if not torrent_id:
            torrent_link = is_uncached.get('torrent_link')
            torrent_id = await (
                self.add_magnet(hash) if has_magnet or not torrent_link
                else self.add_file(torrent_link)
            )

        magnet_info = await self.get_info(torrent_id)

        # Reset TorrentId if not found, might happen if user removes it in debridManager
        if magnet_info.get("error") == 'unknown_ressource':
            logger.warning(
                f"Exception while getting file from Real-Debrid, please retry, for {hash}|{index}: {magnet_info}"
            )
            await database.execute(
                "UPDATE uncached_torrents SET torrentId = :torrent_id WHERE hash = :hash",
                {"torrent_id": "", "hash": hash}
            )
            return None

        # Return early if already downloading
        if magnet_info.get("status") == 'downloading' or magnet_info.get("status") == 'queued':
            logger.info(
                f"File {hash}|{index} is still uncached, please wait until its cached! Status: {magnet_info.get('status')} | Progress: {magnet_info.get('progress')}%"
            )
            return None

        # Select Files
        await self.select_files(torrent_id, magnet_info)
        magnet_info = await self.get_info(torrent_id)
        # Warn if after selecting still nothing selected
        if magnet_info.get("status") == "waiting_files_selection":
            logger.warning(
                f"Exception while selecting files, please visit debrid and select them manually for {hash}|{index}"
            )
        # Update the database with torrent_id and selected index
        largest_file_index = None
        largest_file_size = 0
        for index, file in enumerate(magnet_info["files"]):
            if file["selected"] == 1 and file["bytes"] > largest_file_size:
                largest_file_size = file["bytes"]
                largest_file_index = index
        index = largest_file_index if largest_file_index is not None else 0

        if settings.DATABASE_TYPE == 'sqlite':
            query = """
            UPDATE uncached_torrents 
            SET torrentId = :torrent_id, 
                data = json_set(data, '$.index', json(:index))
            WHERE hash = :hash
            """
        else:  # Assuming PostgreSQL
            query = """
                UPDATE uncached_torrents 
                SET torrentId = :torrent_id, 
                    data = data || jsonb_build_object('index', :index)
                WHERE hash = :hash
                """
        await database.execute(query, {"torrent_id": torrent_id, "index": index, "hash": hash})
        # Skip unrestrict if no links available yet
        if len(magnet_info["links"]) == 0:
            logger.info(
                f"File {hash}|{index} is uncached, please wait until its cached! Status: {magnet_info.get('status')} | Progress: {magnet_info.get('progress')}%"
            )
            return None
        return await self.get_download_link(index, magnet_info)

    async def handle_cached(self, hash: str, index: str):
        torrent_id = await self.add_magnet(hash)
        magnet_info = await self.get_info(torrent_id)
        await self.select_files(torrent_id, magnet_info)
        magnet_info = await self.get_info(torrent_id)
        return await self.get_download_link(index, magnet_info)

    async def generate_download_link(self, hash: str, index: str):
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
            # Check if torrent Uncached
            is_uncached = await check_uncached(hash)
            if is_uncached:
                return await self.handle_uncached(is_uncached, hash, index)
            else:
                return await self.handle_cached(hash, index)
        except Exception as e:
            logger.warning(
                f"Exception while getting download link from Real-Debrid for {hash}|{index}: {e}"
            )
            return None
