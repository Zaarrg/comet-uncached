import time
from typing import Optional

import aiohttp
import asyncio

from RTN import parse

from comet.utils.general import is_video, check_completion, extra_file_pattern, check_uncached, check_index, \
    uncached_db_find_container_id, update_container_id_uncached_db, update_torrent_id_uncached_db, uncached_select_index
from comet.utils.logger import logger
from comet.utils.models import settings


class TorBox:
    def __init__(self, session: aiohttp.ClientSession, debrid_api_key: str):
        session.headers["Authorization"] = f"Bearer {debrid_api_key}"
        self.session = session
        self.proxy = None

        self.api_url = "https://api.torbox.app/v1/api"
        self.debrid_api_key = debrid_api_key

    async def check_premium(self):
        try:
            check_premium = await self.session.get(
                f"{self.api_url}/user/me?settings=false"
            )
            check_premium = await check_premium.text()
            if '"success":true' in check_premium:
                return True
        except Exception as e:
            logger.warning(f"Exception while checking premium status on TorBox: {e}")

        return False

    async def get_instant(self, chunk: list):
        try:
            response = await self.session.get(
                f"{self.api_url}/torrents/checkcached?hash={','.join(chunk)}&format=list&list_files=true"
            )
            return await response.json()
        except Exception as e:
            logger.warning(
                f"Exception while checking hash instant availability on TorBox: {e}"
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

        availability = [response for response in responses if response is not None]

        files = {}

        if type == "series":
            for result in availability:
                if not result["success"] or not result["data"]:
                    continue

                for torrent in result["data"]:
                    torrent_files = torrent["files"]
                    for file in torrent_files:
                        filename = file["name"].split("/")[1]

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

                        files[torrent["hash"]] = {
                            "index": torrent_files.index(file),
                            "title": filename,
                            "size": file["size"],
                            "uncached": False,
                            "complete": None,
                        }

                        break
        else:
            for result in availability:
                if not result["success"] or not result["data"]:
                    continue

                for torrent in result["data"]:
                    torrent_files = torrent["files"]
                    for file in torrent_files:
                        filename = file["name"].split("/")[1]

                        if not is_video(filename):
                            continue

                        if extra_file_pattern.search(filename):
                            continue

                        files[torrent["hash"]] = {
                            "index": torrent_files.index(file),
                            "title": filename,
                            "size": file["size"],
                            "uncached": False,
                        }

                        break

        return files

    async def get_first_files(self, amount: int):
        results = []
        # Amount not needed for all debrid - but just in case
        if amount < 0 or amount > 1000:
            logger.warning(f"Max amount exceeded for retrieving torrents explicitly from All-Debrid")
            return results
        try:
            response = await self.session.get(
                f"{self.api_url}/torrents/mylist?bypass_cache=true"
            )
            torrents = await response.json()
            torrents_data = torrents["data"]

            for file in torrents_data:
                results.append(
                    {
                        "Title": file['name'],
                        "InfoHash": file['hash'],
                        "Size": file["size"],
                        "Tracker": "torbox",
                        "Id": file["id"],
                        "Status": file["download_state"]
                    }
                )
            logger.info(f"Retrieved {len(results)} torrents explicitly from Torbox")
            return results
        except Exception as e:
            logger.warning(
                f"Exception while getting recent files on Torbox: {e}"
            )

    async def add_magnet(self, hash: str):
        # Handle magnet link
        add_magnet = await self.session.post(
            f"{self.api_url}/torrents/createtorrent",
            data={"magnet": f"magnet:?xt=urn:btih:{hash}"},
        )
        add_magnet = await add_magnet.json()
        torrent_id = add_magnet["data"]["torrent_id"]
        if not torrent_id:
            raise Exception(f"Failed to get magnet ID from Torbox: {add_magnet}")
        return torrent_id

    async def add_file(self, torrent_link: str, protocol: str, name: str):
        # Download uncached torrent if it has only a link
        async with self.session.get(torrent_link) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to download torrent, please try another one, status code: {resp.status}")
            torrent_data = await resp.read()

        # Prepare the form data
        form = aiohttp.FormData()
        if protocol == "torrent":
            form.add_field(
                'file',
                torrent_data,
                filename=f"{name}.torrent",
                content_type='application/x-bittorrent'
            )
        elif protocol == "usenet":
            form.add_field(
                'file',
                torrent_data,
                filename=f"{name}.nzb",
                content_type='application/x-nzb'
            )

        add_torrent = await self.session.post(
            f"{self.api_url}/torrents/createtorrent" if protocol != "usenet" else f"{self.api_url}/usenet/createusenetdownload",
            data=form,
        )

        add_torrent = await add_torrent.json()
        torrent_id = add_torrent["data"]["torrent_id"] if protocol != "usenet" else add_torrent["data"]["usenetdownload_id"]
        if not torrent_id:
            raise Exception(f"Failed to get torrent ID from Torbox: {add_torrent}")
        logger.info(
            f"Started caching to Torbox this might take some time: {add_torrent}"
        )
        return torrent_id

    async def get_info(self, torrent_id: Optional[str] = None, hash: Optional[str] = None, protocol: Optional[str] = None):
        try:
            get_torrents = await self.session.get(
                f"{self.api_url}/{'torrents' if protocol == 'torrent' else 'usenet'}/mylist?bypass_cache=true{'&id=' + str(torrent_id) if torrent_id else ''}"
            )
        except Exception as e:
            logger.warning(
                f"Exception while getting file info from Torbox: {e}"
            )
            return None
        if torrent_id:
            return await get_torrents.json()
        else:
            get_torrents = await get_torrents.json()
            torrent_data = None
            for torrent in get_torrents["data"]:
                if torrent["hash"] == hash:
                    torrent_data = torrent
                    break
            return torrent_data

    async def get_download_link(self, index: int, torrent_id: str, protocol: str):
        get_download_link = await self.session.get(
            f"{self.api_url}/{'torrents' if protocol == 'torrent' else 'usenet'}/requestdl?token={self.debrid_api_key}&{'torrent_id' if protocol == 'torrent' else 'usenet_id'}={torrent_id}&file_id={index}&zip=false",
        )
        get_download_link = await get_download_link.json()

        return get_download_link["data"]

    async def handle_uncached(self, is_uncached: dict, hash: str, index: str, debrid_key: str):
        container_id = is_uncached.get('container_id', None)
        torrent_id = is_uncached.get('torrent_id', None)
        has_magnet = is_uncached.get('has_magnet', None)
        protocol = is_uncached.get('protocol')
        name = is_uncached.get('raw_title')

        if not container_id:
            possible_container_id = await uncached_db_find_container_id(debrid_key, hash)
            if possible_container_id == "":
                torrent_link = is_uncached.get('torrent_link')
                container_id = await (
                    self.add_magnet(hash) if has_magnet or not torrent_link
                    else self.add_file(torrent_link, protocol, name)
                )
            else:
                container_id = possible_container_id
            await update_container_id_uncached_db(debrid_key, hash, container_id)
        magnet_info = await self.get_info(container_id, None, protocol)
        # Reset ContainerId if not found, might happen if user removes it in debridManager Code >= 5 Error
        if not magnet_info or magnet_info['data'].get("download_state") == "error" or magnet_info['data'].get("download_state") == "missingFiles" or magnet_info['data'].get("download_state") == "unknown" or "failed" in magnet_info['data'].get("download_state"):
            logger.warning(
                f"Exception while getting file from Torbox, please retry, for {hash}|{index}: {magnet_info}"
            )
            await update_container_id_uncached_db(debrid_key, hash, "")
            await update_torrent_id_uncached_db(debrid_key, hash, index, "")
            return None

        magnet_info = magnet_info['data']

        if protocol == "usenet":
            max_attempts = settings.USENET_REFRESH_ATTEMPTS

            for attempt in range(max_attempts):
                download_finished = magnet_info.get("download_finished")
                files = magnet_info.get("files") or []

                if download_finished and len(files) > 0:
                    break

                logger.info(
                    f"File {hash}|{index} is still uncached, please wait."
                    f" Status: {magnet_info.get('download_state')} |"
                    f" Progress: {int(magnet_info.get('progress') * 100)}%. Attempt {attempt+1}/{max_attempts}"
                )

                time.sleep(4)

                magnet_info_result = await self.get_info(container_id, None, protocol)
                if not magnet_info_result:
                    logger.warning(
                        f"Exception while getting file from Torbox, please retry, for {hash}|{index}"
                    )
                    return None
                magnet_info = magnet_info_result['data']
            else:
                logger.warning(
                    f"Download was not finished after {max_attempts} attempts for {hash}|{index}"
                )
                return None
        else:
            if not magnet_info.get("download_finished") or not magnet_info.get("files"):
                logger.info(
                    f"File {hash}|{index} is still uncached, please wait."
                    f" Status: {magnet_info.get('download_state')} |"
                    f" Progress: {int(magnet_info.get('progress') * 100)}%"
                )
                return None
        # Select correct file after downloading - Torbox does not show files info pre download finished
        if not torrent_id:
            # Select right index by matching titles
            selected_id = await uncached_select_index(magnet_info["files"], index, is_uncached["name"], is_uncached["episode"], is_uncached["season"], is_uncached["parsed_data"], "torbox")
            # Save torrentId
            torrent_id = selected_id
            await update_torrent_id_uncached_db(debrid_key, hash, index, selected_id)

        return await self.get_download_link(torrent_id, container_id, protocol)

    async def handle_cached(self, hash: str, index: str):
        torrent_data = await self.get_info(None, hash, "torrent")
        if not torrent_data:
            torrent_data = {'id': await self.add_magnet(hash)}
        return await self.get_download_link(index, torrent_data['id'], "torrent")

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
                f"Exception while getting download link from TorBox for {hash}|{index}: {e}"
            )
