import aiohttp
import asyncio

from RTN import parse

from comet.utils.general import is_video, check_completion, check_uncached, uncached_db_find_container_id, \
    update_container_id_uncached_db, update_torrent_id_uncached_db, uncached_select_index, check_index, \
    extra_file_pattern
from comet.utils.logger import logger
from comet.utils.models import settings


class AllDebrid:
    def __init__(self, session: aiohttp.ClientSession, debrid_api_key: str):
        session.headers["Authorization"] = f"Bearer {debrid_api_key}"
        self.session = session
        self.proxy = None

        self.api_url = "http://api.alldebrid.com/v4"
        self.agent = "comet"

    async def check_premium(self):
        try:
            check_premium = await self.session.get(
                f"{self.api_url}/user?agent={self.agent}"
            )
            check_premium = await check_premium.text()
            if '"isPremium":true' in check_premium:
                return True
        except Exception as e:
            logger.warning(
                f"Exception while checking premium status on All-Debrid: {e}"
            )

        return False

    async def get_instant(self, chunk: list):
        try:
            get_instant = await self.session.get(
                f"{self.api_url}/magnet/instant?agent={self.agent}&magnets[]={'&magnets[]='.join(chunk)}"
            )
            return await get_instant.json()
        except Exception as e:
            logger.warning(
                f"Exception while checking hashes instant availability on All-Debrid: {e}"
            )

    async def get_files(
        self, torrent_hashes: list, type: str, season: str, episode: str, kitsu: bool
    ):
        chunk_size = 500
        chunks = [
            torrent_hashes[i : i + chunk_size]
            for i in range(0, len(torrent_hashes), chunk_size)
        ]

        tasks = []
        for chunk in chunks:
            tasks.append(self.get_instant(chunk))

        responses = await asyncio.gather(*tasks)

        availability = [response for response in responses if response]

        files = {}

        if type == "series":
            for result in availability:
                if "status" not in result or result["status"] != "success":
                    continue

                for magnet in result["data"]["magnets"]:
                    if not magnet["instant"]:
                        continue

                    for file in magnet["files"]:
                        filename = file["n"]
                        pack = False
                        if "e" in file:  # PACK
                            filename = file["e"][0]["n"]
                            pack = True

                        if not is_video(filename):
                            continue

                        if extra_file_pattern.search(filename):
                            continue

                        filename_parsed = parse(filename)
                        if episode not in filename_parsed.episodes:
                            continue

                        if kitsu:
                            if filename_parsed.seasons:
                                continue
                        else:
                            if season not in filename_parsed.seasons:
                                continue

                        files[magnet["hash"]] = {
                            "index": magnet["files"].index(file),
                            "title": filename,
                            "size": file["e"][0]["s"] if pack else file["s"],
                            "uncached": False,
                            "complete": None,
                        }

                        break
        else:
            for result in availability:
                if "status" not in result or result["status"] != "success":
                    continue

                for magnet in result["data"]["magnets"]:
                    if not magnet["instant"]:
                        continue

                    for file in magnet["files"]:
                        filename = file["n"]

                        if not is_video(filename):
                            continue

                        if extra_file_pattern.search(filename):
                            continue

                        files[magnet["hash"]] = {
                            "index": magnet["files"].index(file),
                            "title": filename,
                            "size": file["s"],
                            "uncached": False,
                        }

                        break

        return files

    async def get_first_files(self, amount: int):
        results = []
        # Amount not needed for all debrid - but just in case
        if amount < 0 or amount > 5000:
            logger.warning(f"Max amount exceeded for retrieving torrents explicitly from All-Debrid")
            return results
        try:
            response = await self.session.get(
                f"{self.api_url}/magnet/status?agent={self.agent}",
            )
            torrents = await response.json()
            torrents_data = torrents["data"]["magnets"]

            for file in torrents_data:
                results.append(
                    {
                        "Title": file['filename'],
                        "InfoHash": file['hash'],
                        "Size": file["size"],
                        "Tracker": "alldebrid",
                        "Id": file["id"],
                        "Status": file["status"]
                    }
                )
            logger.info(f"Retrieved {len(results)} torrents explicitly from All-Debrid")
            return results
        except Exception as e:
            logger.warning(
                f"Exception while getting recent files on Real-Debrid: {e}"
            )

    async def add_magnet(self, hash: str):
        upload_magnet = await self.session.get(
            f"{self.api_url}/magnet/upload?agent=comet&magnets[]={hash}",
            proxy=self.proxy,
        )
        upload_magnet = await upload_magnet.json()
        return upload_magnet['data']['magnets'][0]['id']

    async def add_file(self, torrent_link: str):
        # Download uncached torrent if it has only a link
        async with self.session.get(torrent_link) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to download torrent, please try another one, status code: {resp.status}")
            torrent_data = await resp.read()

        # Prepare the form data
        form = aiohttp.FormData()
        form.add_field(
            'files[]',
            torrent_data,
            filename="torrent_file.torrent",
            content_type='application/x-bittorrent'
        )

        add_torrent = await self.session.post(
            f"{self.api_url}/magnet/upload/file?agent={self.agent}",
            data=form,
            proxy=self.proxy,
        )
        add_torrent = await add_torrent.json()
        torrent_id = add_torrent["data"]["files"][0]["id"]
        if not torrent_id:
            raise Exception(f"Failed to get torrent ID from All-debrid: {add_torrent}")
        logger.info(
            f"Started caching to All-Debrid this might take some time: {add_torrent}"
        )
        return torrent_id

    async def get_info(self, torrent_id: str):
        get_magnet_status = await self.session.get(
            f"{self.api_url}/magnet/status?agent=comet&id={torrent_id}",
            proxy=self.proxy,
        )
        return await get_magnet_status.json()

    async def get_download_link(self, index: str, magnet_info: dict):
        unlock_link = await self.session.get(
            f"{self.api_url}/link/unlock?agent=comet&link={magnet_info['data']['magnets']['links'][int(index)]['link']}",
            proxy=self.proxy,
        )
        unlock_link = await unlock_link.json()
        return unlock_link["data"]["link"]

    async def handle_uncached(self, is_uncached: dict, hash: str, index: str, debrid_key: str):
        container_id = is_uncached.get('container_id', None)
        torrent_id = is_uncached.get('torrent_id', None)
        has_magnet = is_uncached.get('has_magnet', None)

        if not container_id:
            possible_container_id = await uncached_db_find_container_id(debrid_key, hash)
            if possible_container_id == "":
                torrent_link = is_uncached.get('torrent_link')
                container_id = await (
                    self.add_magnet(hash) if has_magnet or not torrent_link
                    else self.add_file(torrent_link)
                )
            else:
                container_id = possible_container_id
            await update_container_id_uncached_db(debrid_key, hash, container_id)

        magnet_info = await self.get_info(container_id)

        # Reset ContainerId if not found, might happen if user removes it in debridManager Code >= 5 Error
        if magnet_info.get("status") != "success" or int(magnet_info["data"]["magnets"]["statusCode"]) >= 5:
            logger.warning(
                f"Exception while getting file from All-Debrid, please retry, for {hash}|{index}: {magnet_info}"
            )
            await update_container_id_uncached_db(debrid_key, hash, "")
            await update_torrent_id_uncached_db(debrid_key, hash, index, "")
            return None

        magnet_data = magnet_info["data"]["magnets"]
        # Return early if already downloading Code 0-4 Processing
        if 0 <= int(magnet_data.get("statusCode")) < 4:
            download_percentage = 0
            if int(magnet_data.get("statusCode")) != 0:
                download_percentage = (magnet_data.get("downloaded") / magnet_data.get("size")) * 100
            logger.info(
                f"File {hash}|{index} is still uncached, please wait until its cached! Status: {magnet_data.get('status')} | Progress: {download_percentage:.2f}%"
            )
            return None

        # Select correct file after downloading - Alldebrid does not show files info pre download finished
        if not torrent_id:
            # Select right index by matching titles
            selected_id = await uncached_select_index(magnet_data["links"], index, is_uncached["name"], is_uncached["episode"], is_uncached["season"], is_uncached["parsed_data"], "alldebrid")
            # Save torrentId (torrent id = index in links list)
            torrent_id = selected_id
            await update_torrent_id_uncached_db(debrid_key, hash, index, selected_id)

        return await self.get_download_link(torrent_id, magnet_info)

    async def handle_cached(self, hash: str, index: str):
        torrent_id = await self.add_magnet(hash)
        magnet_info = await self.get_info(torrent_id)
        return await self.get_download_link(index, magnet_info)

    async def generate_download_link(self, hash: str, index: str, debrid_key: str):
        try:
            check_blacklisted = await self.session.get(
                f"{self.api_url}/magnet/upload?agent=comet&magnets[]={hash}"
            )
            check_blacklisted = await check_blacklisted.text()
            if "NO_SERVER" in check_blacklisted:
                self.proxy = settings.DEBRID_PROXY_URL
                if not self.proxy:
                    logger.warning(
                        "All-Debrid blacklisted server's IP. No proxy found."
                    )
                else:
                    logger.warning(
                        f"All-Debrid blacklisted server's IP. Switching to proxy {self.proxy} for {hash}|{index}"
                    )

            # Check if torrent Uncached
            is_uncached = await check_uncached(hash, index, debrid_key)
            if is_uncached:
                return await self.handle_uncached(is_uncached, hash, index, debrid_key)
            else:
                index = await check_index(hash, index, debrid_key)
                return await self.handle_cached(hash, index)
        except Exception as e:
            logger.warning(
                f"Exception while getting download link from All-Debrid for {hash}|{index}: {e}"
            )
