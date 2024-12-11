import aiohttp
import asyncio

from RTN import parse

from comet.utils.general import is_video, check_completion, check_uncached, uncached_db_find_container_id, \
    update_container_id_uncached_db, update_torrent_id_uncached_db, uncached_select_index, check_index, \
    extra_file_pattern
from comet.utils.logger import logger


class Premiumize:
    def __init__(self, session: aiohttp.ClientSession, debrid_api_key: str):
        self.session = session
        self.proxy = None

        self.api_url = "https://premiumize.me/api"
        self.debrid_api_key = debrid_api_key

    async def check_premium(self):
        try:
            check_premium = await self.session.get(
                f"{self.api_url}/account/info?apikey={self.debrid_api_key}"
            )
            check_premium = await check_premium.text()
            if (
                '"status":"success"' in check_premium
                and '"premium_until":null' not in check_premium
            ):
                return True
        except Exception as e:
            logger.warning(
                f"Exception while checking premium status on Premiumize: {e}"
            )

        return False

    async def get_instant(self, chunk: list):
        try:
            response = await self.session.get(
                f"{self.api_url}/cache/check?apikey={self.debrid_api_key}&items[]={'&items[]='.join(chunk)}"
            )

            response = await response.json()
            response["hashes"] = chunk

            return response
        except Exception as e:
            logger.warning(
                f"Exception while checking hash instant availability on Premiumize: {e}"
            )

    async def get_files(
        self, torrent_hashes: list, type: str, season: str, episode: str, kitsu: bool
    ):
        chunk_size = 100
        chunks = [
            torrent_hashes[i : i + chunk_size]
            for i in range(0, len(torrent_hashes), chunk_size)
        ]

        tasks = []
        for chunk in chunks:
            tasks.append(self.get_instant(chunk))

        responses = await asyncio.gather(*tasks)

        availability = []
        for response in responses:
            if not response:
                continue

            availability.append(response)

        files = {}

        if type == "series":
            for result in availability:
                if result["status"] != "success":
                    continue

                responses = result["response"]
                filenames = result["filename"]
                filesizes = result["filesize"]
                hashes = result["hashes"]
                for index, response in enumerate(responses):
                    if not response:
                        continue

                    if not filesizes[index]:
                        continue

                    filename = filenames[index]

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

                    files[hashes[index]] = {
                        "index": f"{season}|{episode}",
                        "title": filename,
                        "size": int(filesizes[index]),
                        "uncached": False,
                        "complete": None,
                    }
        else:
            for result in availability:
                if result["status"] != "success":
                    continue

                responses = result["response"]
                filenames = result["filename"]
                filesizes = result["filesize"]
                hashes = result["hashes"]
                for index, response in enumerate(responses):
                    if response is False:
                        continue

                    if not filesizes[index]:
                        continue

                    filename = filenames[index]

                    if extra_file_pattern.search(filename):
                        continue

                    files[hashes[index]] = {
                        "index": 0,
                        "title": filename,
                        "size": int(filesizes[index]),
                        "uncached": False,
                    }

        return files

    async def add_magnet(self, hash: str):
        add_magnet = await self.session.post(
            f"{self.api_url}/transfer/directdl?apikey={self.debrid_api_key}&src=magnet:?xt=urn:btih:{hash}",
        )
        return await add_magnet.json()

    async def add_magnet_uncached(self, hash: str):
        add_magnet = await self.session.post(
            f"{self.api_url}/transfer/create?apikey={self.debrid_api_key}&src=magnet:?xt=urn:btih:{hash}",
        )
        return await add_magnet.json()

    async def add_file(self, torrent_link: str):
        # Download uncached torrent if it has only a link
        async with self.session.get(torrent_link) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to download torrent, please try another one, status code: {resp.status}")
            torrent_data = await resp.read()

        # Prepare the form data
        form = aiohttp.FormData()
        form.add_field(
            'file',  # Field name as per your browser's observation
            torrent_data,
            filename='torrent_file.torrent',
            content_type='application/x-bittorrent'
        )

        add_torrent = await self.session.post(
            f"{self.api_url}/transfer/create?apikey={self.debrid_api_key}",
            data=form,
            proxy=self.proxy,
        )
        add_torrent = await add_torrent.json()

        if add_torrent["status"] == "error":
            logger.error(f"Failed to upload torrent file to Premiumize: {add_torrent}")
            return None

        return add_torrent

    async def get_info(self, torrent_id: str):
        get_magnet_status = await self.session.get(
            f"{self.api_url}/transfer/list?apikey={self.debrid_api_key}",
        )
        get_magnet_status = await get_magnet_status.json()
        get_magnet_status = next((item for item in get_magnet_status['transfers'] if item['id'] == torrent_id), None)
        return get_magnet_status

    async def get_download_link(self, index: str, add_magnet: dict):
        # Only for cached results - Uncached have use uncached_select_index()
        season = None
        if "|" in index:
            index = index.split("|")
            season = int(index[0])
            episode = int(index[1])

        content = add_magnet["content"]
        for file in content:
            filename = file["path"]
            if "/" in filename:
                filename = filename.split("/")[1]

            if not is_video(filename):
                content.remove(file)
                continue

            if season is not None:
                filename_parsed = parse(filename)
                if (
                        season in filename_parsed.seasons
                        and episode in filename_parsed.episodes
                ):
                    return file["link"]

        max_size_item = max(content, key=lambda x: x["size"])
        return max_size_item["link"]

    async def handle_uncached(self, is_uncached: dict, hash: str, index: str, debrid_key: str):
        container_id = is_uncached.get('container_id', None)
        torrent_id = is_uncached.get('torrent_id', None)
        has_magnet = is_uncached.get('has_magnet', None)

        if not container_id:
            possible_container_id = await uncached_db_find_container_id(debrid_key, hash)
            if possible_container_id == "":
                torrent_link = is_uncached.get('torrent_link')
                container = await (
                    self.add_magnet_uncached(hash) if has_magnet or not torrent_link
                    else self.add_file(torrent_link)
                )
                if not container:
                    return None
                container_id = container["id"]
            else:
                container_id = possible_container_id
            await update_container_id_uncached_db(debrid_key, hash, container_id)

        magnet_info = await self.get_info(container_id)
        # Reset ContainerId if not found, might happen if user removes it in debridManager Code >= 5 Error
        if magnet_info.get("status") != "running" and magnet_info.get("status") != "finished":
            logger.warning(
                f"Exception while getting file from Premiumize, please retry, for {hash}|{index}: {magnet_info}"
            )
            await update_container_id_uncached_db(debrid_key, hash, "")
            await update_torrent_id_uncached_db(debrid_key, hash, index, "")
            return None

        # Return early if already downloading Code 0-4 Processing
        if magnet_info.get("status") != "finished" and int(magnet_info.get("progress")) < 1:
            download_percentage = magnet_info.get("progress") * 100
            logger.info(
                f"File {hash}|{index} is still uncached, please wait until its cached! Status: {magnet_info.get('status')} | Progress: {download_percentage:.2f}%"
            )
            return None

        # Add the Hash as directdl - Returns files
        magnet_info = await self.add_magnet(hash)
        # Select correct file after downloading - Premiumize does not show files info pre download finished
        if not torrent_id:
            # Select right index
            selected_id = await uncached_select_index(magnet_info["content"], index, is_uncached["name"], is_uncached["episode"], is_uncached["season"], is_uncached["parsed_data"], "premiumize")
            # Save torrentId (torrent id = index in links list)
            torrent_id = selected_id
            await update_torrent_id_uncached_db(debrid_key, hash, index, selected_id)

        return magnet_info["content"][torrent_id]["link"]

    async def handle_cached(self, hash: str, index: str):
        magnet_info = await self.add_magnet(hash)
        return await self.get_download_link(index, magnet_info)

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
                f"Exception while getting download link from Premiumize for {hash}|{index}: {e}"
            )
