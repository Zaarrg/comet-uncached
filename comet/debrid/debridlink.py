import aiohttp
import asyncio

from RTN import parse
from aiohttp import FormData

from comet.utils.general import is_video, check_uncached, remove_file_extension, update_torrent_id_uncached_db, \
    update_container_id_uncached_db, uncached_db_find_container_id, uncached_select_index, check_index
from comet.utils.logger import logger


class DebridLink:
    def __init__(self, session: aiohttp.ClientSession, debrid_api_key: str):
        session.headers["Authorization"] = f"Bearer {debrid_api_key}"
        self.session = session
        self.proxy = None

        self.api_url = "https://debrid-link.com/api/v2"

    async def check_premium(self):
        try:
            check_premium = await self.session.get(f"{self.api_url}/account/infos")
            check_premium = await check_premium.text()
            if '"accountType":1' in check_premium:
                return True
        except Exception as e:
            logger.warning(
                f"Exception while checking premium status on Debrid-Link: {e}"
            )

        return False

    async def get_instant(self, chunk: list):
        responses = []
        for hash in chunk:
            try:
                # Return early if download started. Prevents Debridlink to stop ongoing downloads
                possible_container_id = await uncached_db_find_container_id("debridlink", hash)
                if possible_container_id != "":
                    continue

                add_torrent = await self.session.post(
                    f"{self.api_url}/seedbox/add",
                    data={"url": hash, "wait": True, "async": True},
                )
                add_torrent = await add_torrent.json()

                torrent_id = add_torrent["value"]["id"]
                await self.session.delete(f"{self.api_url}/seedbox/{torrent_id}/remove")

                responses.append(add_torrent)
            except:
                pass

        return responses

    async def get_first_files(self, amount: int):
        results = []
        if amount < 0 or amount > 50:
            logger.warning(f"Max amount exceeded for retrieving torrents explicitly from Debrid Link")
            return results
        try:
            response = await self.session.get(
                f"{self.api_url}/seedbox/list",
                params={"perPage": amount}
            )
            torrents = await response.json()
            for file in torrents["value"]:
                results.append(
                    {
                        "Title": file['name'],
                        "InfoHash": file['hashString'],
                        "Size": file["totalSize"],
                        "Tracker": "debridlink",
                    }
                )
            logger.info(f"Retrieved {len(results)} torrents explicitly from Debrid Link")
            return results
        except Exception as e:
            logger.warning(
                f"Exception while getting recent files on Debrid Link: {e}"
            )

    async def get_files(
            self, torrent_hashes: list, type: str, season: str, episode: str, kitsu: bool
    ):
        chunk_size = 10
        chunks = [
            torrent_hashes[i: i + chunk_size]
            for i in range(0, len(torrent_hashes), chunk_size)
        ]

        tasks = []
        for chunk in chunks:
            tasks.append(self.get_instant(chunk))

        responses = await asyncio.gather(*tasks)

        availability = []
        for response_list in responses:
            for response in response_list:
                availability.append(response)

        files = {}

        if type == "series":
            for result in availability:
                torrent_files = result["value"]["files"]
                for file in torrent_files:
                    if file["downloadPercent"] != 100:
                        continue

                    filename = file["name"]

                    if not is_video(filename):
                        continue

                    if "sample" in filename.lower():
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

                    files[result["value"]["hashString"]] = {
                        "index": torrent_files.index(file),
                        "title": filename,
                        "size": file["size"],
                        "uncached": False,
                        "complete": None,
                    }

                    break
        else:
            for result in availability:
                value = result["value"]
                torrent_files = value["files"]
                for file in torrent_files:
                    if file["downloadPercent"] != 100:
                        continue

                    filename = file["name"]

                    if not is_video(filename):
                        continue

                    if "sample" in filename.lower():
                        continue

                    files[value["hashString"]] = {
                        "index": torrent_files.index(file),
                        "title": filename,
                        "size": file["size"],
                        "uncached": False,
                    }

        return files

    async def add_magnet(self, hash: str):
        add_torrent = await self.session.post(
            f"{self.api_url}/seedbox/add", data={"url": f"magnet:?xt=urn:btih:{hash}", "async": True}
        )
        return await add_torrent.json()

    async def add_file(self, torrent_link: str):
        # Download the torrent file
        async with self.session.get(torrent_link) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to download torrent, please try another one, status code: {resp.status}")
            torrent_data = await resp.read()

        # Create a FormData object to handle multipart/form-data encoding
        data = FormData()
        data.add_field(
            'file',
            torrent_data,
            filename='torrent.torrent',
            content_type='application/x-bittorrent'
        )
        data.add_field('async', 'true')

        # Send the PUT request with the multipart/form-data
        add_torrent = await self.session.post(
            f"{self.api_url}/seedbox/add",
            data=data,
            proxy=self.proxy,
        )
        return await add_torrent.json()

    async def get_info(self, container_id: str):
        get_magnet_info = await self.session.get(
            f"{self.api_url}/seedbox/list",
            params={'ids': container_id},
            proxy=self.proxy
        )
        return await get_magnet_info.json()

    async def handle_uncached(self, is_uncached: dict, hash: str, index: str, debrid_key: str):
        container_id = is_uncached.get('container_id', None)
        torrent_id = is_uncached.get('torrent_id', None)
        has_magnet = is_uncached.get('has_magnet', None)

        if not container_id:
            possible_container_id = await uncached_db_find_container_id(debrid_key, hash)
            if possible_container_id == "":
                torrent_link = is_uncached.get('torrent_link')
                container = await (
                    self.add_magnet(hash) if has_magnet or not torrent_link
                    else self.add_file(torrent_link)
                )
                if container.get("value", None) is None:
                    raise Exception(f"Failed to upload torrent to Debrid-Link: {hash} | {container}")
                container_id = container["value"]["id"]
                if not container_id:
                    raise Exception(f"Failed to get magnet ID from Debrid-Link: {hash}")
            else:
                container_id = possible_container_id
            await update_container_id_uncached_db(debrid_key, hash, container_id)

        # Get info about container
        magnet_info = await self.get_info(container_id)

        # Reset ContainerId if not found, might happen if user removes it in debridManager
        if not magnet_info["success"] or len(magnet_info["value"]) <= 0:
            logger.warning(
                f"Exception while getting file from Debrid Link, please retry, for {hash}|{index}: {magnet_info}"
            )
            await update_container_id_uncached_db(debrid_key, hash, "")
            return None

        magnet_value = magnet_info["value"][0]
        if not torrent_id:
            # Warn if its not downloading
            if magnet_value["wait"]:
                logger.warning(
                    f"Exception while selecting video files, please visit debrid and select them manually for {hash}|{index}"
                )
                return None
            # Status 2 = checking, Status 4 = downloading, Status 6 = seeding, Status 100 = downloaded
            if int(magnet_value["status"]) != 4 and int(magnet_value["status"]) != 6 and int(magnet_value["status"]) != 100:
                logger.warning(
                    f"Exception while selecting video files, download not started, waiting for download to start {hash}|{index}"
                )
                return None
            # Select the right file and get its index by matching titles
            selected_index = await uncached_select_index(magnet_value["files"], index, is_uncached["name"], is_uncached["episode"], is_uncached["parsed_data"], "debridlink")
            # Save torrentId
            torrent_id = selected_index
            await update_torrent_id_uncached_db(debrid_key, hash, index, selected_index)

        # Return early if already downloading
        if magnet_value["files"][int(torrent_id)]["downloadPercent"] != 100:
            progress = magnet_value["files"][int(torrent_id)]["downloadPercent"]
            logger.info(
                f"File {hash}|{index} is still uncached, please wait until its cached! Progress: {progress}%"
            )
            return None

        # Return Link
        return magnet_value["files"][int(torrent_id)]["downloadUrl"]

    async def handle_cached(self, hash: str, index: str):
        torrent_data = await self.add_magnet(hash)
        return torrent_data["value"]["files"][int(index)]["downloadUrl"]

    async def generate_download_link(self, hash: str, index: str, debrid_key: str):
        try:
            # Check if torrent Uncached
            is_uncached = await check_uncached(hash, index, debrid_key)
            if is_uncached:
                return await self.handle_uncached(is_uncached, hash, index, debrid_key)
            else:
                index = await check_index(hash, index, debrid_key)
                return await self.handle_cached(hash, index)
        except Exception as e:
            logger.warning(
                f"Exception while getting download link from Debrid-Link for {hash}|{index}: {e}"
            )
