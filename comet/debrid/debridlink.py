import aiohttp
import asyncio

from RTN import parse
from aiohttp import FormData

from comet.utils.general import is_video, check_uncached
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
        self, torrent_hashes: list, type: str, season: str, episode: str, kitsu: bool
    ):
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

                        filename_parsed = parse(filename)
                        if episode not in filename_parsed.episodes:
                            continue

                        if kitsu:
                            if filename_parsed.seasons:
                                continue
                        else:
                            if season not in filename_parsed.seasons:
                                continue

                        files[hash] = {
                            "index": torrent_data["files"].index(file),
                            "title": filename,
                            "size": file["size"],
                            "uncached": False,
                        }

                        break
        else:
            for result in availability:
                for hash, torrent_data in result["value"].items():
                    for file in torrent_data["files"]:
                        filename = file["name"]

                        if not is_video(filename):
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
            f"{self.api_url}/seedbox/add", data={"url": hash, "async": True}
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
        has_magnet = is_uncached.get('has_magnet', None)
        if not torrent_id:
            if has_magnet:
                file_value = await self.add_magnet(hash)
            else:
                torrent_link = is_uncached.get('torrent_link')
                file_value = await self.add_file(torrent_link)

            files = file_value.get('files', [])
            # Selects file by size to save index
            largest_file = max(
                (file for file in files if file.get('wanted', False)),
                key=lambda x: x.get('size', 0),
                default=None
            )
            if not largest_file:
                raise Exception(f"Exception while selecting files, please visit debrid and select them manually for {hash}")

            index = files.index(largest_file)
            torrent_id = largest_file['id']
            await database.execute(f"""
            UPDATE uncached_torrents 
            SET torrentId = :torrent_id, 
                data = {'json_set' if settings.DATABASE_TYPE == 'sqlite' else 'jsonb_set'}(
                    {'data' if settings.DATABASE_TYPE == 'sqlite' else "CAST(data AS jsonb)"},
                    '{{index}}',
                    {'json(:index)' if settings.DATABASE_TYPE == 'sqlite' else 'to_jsonb(:index)'}
                )
            WHERE hash = :hash
            """, {"torrent_id": torrent_id, "index": index, "hash": hash})
            logger.info(
                f"File {hash}|{index} is uncached, please wait until its cached! Is Downloaded: {largest_file['downloaded']} | Progress: {largest_file['downloadPercent']}%"
            )
            return None

        magnet_value = await self.get_info(torrent_id)
        files = magnet_value.get('files', [])
        file = next((file for file in files if file['id'] == torrent_id), None)
        # Reset TorrentId if not found, might happen if user removes it in debridManager
        if len(files) == 0 or not file:
            logger.warning(
                f"Exception while getting file from Real-Debrid, please retry, for {hash}|{index}: {magnet_value}"
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
