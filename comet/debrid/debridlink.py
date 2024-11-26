import aiohttp
import asyncio

from RTN import parse
from aiohttp import FormData

from comet.utils.general import is_video, check_uncached, check_completion, remove_file_extension
from comet.utils.logger import logger
from comet.utils.models import database, settings


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
        try:
            get_instant = await self.session.get(
                f"{self.api_url}/seedbox/cached?url={','.join(chunk)}"
            )
            return await get_instant.json()
        except Exception as e:
            logger.warning(
                f"Exception while checking hashes instant availability on Debrid-Link: {e}"
            )

    async def get_first_files(self, amount: int):
        results = []
        if amount < 20 or amount > 50:
            logger.warning(f"Max amount exceeded for retrieving torrents explicitly from Debrid-Link")
            return results
        try:
            response = await self.session.get(
                f"{self.api_url}/seedbox/list",
                params={"perPage": amount}
            )
            torrents = await response.json()

            for torrent in torrents["value"]:
                results.append(
                    {
                        "Title": torrent['name'],
                        "InfoHash": torrent['hashString'],
                        "Size": torrent["totalSize"],
                        "Tracker": "Debrid-Link",
                    }
                )
            logger.info(f"Retrieved {len(results)} torrents explicitly from Debrid-Link")
            return results
        except Exception as e:
            logger.warning(
                f"Exception while getting recent files on Debrid-Link: {e}"
            )

    async def get_files(
        self, torrents_by_hashes: dict, type: str, season: str, episode: str, kitsu: bool
    ):
        torrent_hashes = list(torrents_by_hashes.keys())
        chunk_size = 250
        chunks = [
            torrent_hashes[i : i + chunk_size]
            for i in range(0, len(torrent_hashes), chunk_size)
        ]

        tasks = []
        for chunk in chunks:
            tasks.append(self.get_instant(chunk))

        responses = await asyncio.gather(*tasks)

        availability = [
            response for response in responses if response and response.get("success")
        ]

        files = {}

        if type == "series":
            for result in availability:
                for hash, torrent_data in result["value"].items():
                    for file in torrent_data["files"]:
                        filename = file["name"]

                        if not is_video(filename):
                            continue

                        if "sample" in filename:
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

                        torrent_name_parsed = parse(torrents_by_hashes[hash]["Title"])
                        files[hash] = {
                            "index": torrent_data["files"].index(file),
                            "title": filename,
                            "size": file["size"],
                            "uncached": False,
                            "complete": torrent_name_parsed.complete or check_completion(torrent_name_parsed.raw_title, season),
                        }

                        break
        else:
            for result in availability:
                for hash, torrent_data in result["value"].items():
                    for file in torrent_data["files"]:
                        filename = file["name"]

                        if not is_video(filename):
                            continue

                        if "sample" in filename:
                            continue

                        files[hash] = {
                            "index": torrent_data["files"].index(file),
                            "title": filename,
                            "size": file["size"],
                            "uncached": False,
                        }

                        break

        return files

    async def get_info(self, torrent_id: str):
        get_magnet_info = await self.session.get(
            f"{self.api_url}/seedbox/list",
            params={"ids": torrent_id},
            proxy=self.proxy
        )
        info = await get_magnet_info.json()
        return info["value"][0]

    async def add_magnet(self, hash: str):
        add_torrent = await self.session.post(
            f"{self.api_url}/seedbox/add", data={"url": f"magnet:?xt=urn:btih:{hash}", "async": True}
        )
        add_torrent = await add_torrent.json()
        return add_torrent["value"]

    async def add_file(self, torrent_link: str):
        async with self.session.get(torrent_link) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to download torrent, please try another one, status code: {resp.status}")
            torrent_data = await resp.read()

        form = FormData()
        form.add_field('file', torrent_data, filename='torrent.torrent', content_type='application/x-bittorrent')
        form.add_field('async', 'true')

        add_torrent = await self.session.post(
            f"{self.api_url}/seedbox/add", data=form
        )
        add_torrent = await add_torrent.json()
        return add_torrent["value"]

    async def handle_uncached(self, is_uncached: dict, hash: str, index: str):
        torrent_id = is_uncached.get('torrent_id', None)
        torrent_link = is_uncached.get('torrent_link', None)
        has_magnet = is_uncached.get('has_magnet', None)
        if not torrent_id:
            if has_magnet or not torrent_link:
                file_value = await self.add_magnet(hash)
            else:
                file_value = await self.add_file(torrent_link)

            files = file_value.get('files', [])
            # Selects file index
            torrent_data = is_uncached.get('torrent_data', None)
            selected_index = index
            files = [file for file in files if file.get('wanted', True)]

            for i, file in enumerate(files):
                file_name = file["name"]
                if file_name in torrent_data.get("title") or remove_file_extension(file_name) == torrent_data.get("title"):
                    selected_index = i
                    break
            index = int(selected_index)
            torrent_id = files[index]['id']
            if settings.DATABASE_TYPE == 'sqlite':
                query = """
                        INSERT OR IGNORE INTO uncached_torrents (hash, torrentId, data)
                        VALUES (:hash, :torrent_id, json('{"index": ' || :index || '}'))
                        ON CONFLICT(hash) DO UPDATE SET
                        torrentId = :torrent_id,
                        data = json_patch(data, json('{"index": ' || :index || '}'))
                        """
            else:  # PostgreSQL
                query = """
                        INSERT INTO uncached_torrents (hash, torrentId, data)
                        VALUES (:hash, :torrent_id, jsonb_build_object('index', :index::jsonb))
                        ON CONFLICT (hash) DO UPDATE SET
                        torrentId = EXCLUDED.torrentId,
                        data = uncached_torrents.data || jsonb_build_object('index', :index::jsonb)
                        """
            await database.execute(query, {"torrent_id": torrent_id, "index": str(index), "hash": hash})
            if files[index]['downloadPercent'] != 100:
                logger.info(
                    f"File {hash}|{index} is uncached, please wait until its cached! Is Downloaded: {files[index]['downloaded']} | Progress: {files[index]['downloadPercent']}%"
                )
                return None

        magnet_value = await self.get_info(torrent_id)
        files = magnet_value.get('files', [])
        file = next((file for file in files if file['id'] == torrent_id), None)
        # Reset TorrentId if not found, might happen if user removes it in debridManager
        if len(files) == 0 or not file:
            logger.warning(
                f"Exception while getting file from Debrid Link, please retry, for {hash}|{index}: {magnet_value}"
            )
            await database.execute(
                "UPDATE uncached_torrents SET torrentId = :torrent_id WHERE hash = :hash",
                {"torrent_id": "", "hash": hash}
            )
            return None

        if file['downloadPercent'] == 100:
            return file['downloadUrl']
        else:
            logger.info(
                f"File {hash}|{index} is still uncached, please wait until its cached! Is Downloaded: {file['downloaded']} | Progress: {file['downloadPercent']}%"
            )
            return None

    async def handle_cached(self, hash: str, index: str):
        magnet_value = await self.add_magnet(hash)
        return magnet_value["files"][int(index)]["downloadUrl"]

    async def generate_download_link(self, hash: str, index: str):
        try:
            is_uncached = await check_uncached(hash)
            if is_uncached:
                return await self.handle_uncached(is_uncached, hash, index)
            else:
                return await self.handle_cached(hash, index)
        except Exception as e:
            logger.warning(
                f"Exception while getting download link from Debrid-Link for {hash}|{index}: {e}"
            )
