import asyncio
import hashlib
import json
import time
import uuid
import aiohttp
import httpx

import os
import orjson

from fastapi import APIRouter, Request, Header
from fastapi.responses import (
    RedirectResponse,
    StreamingResponse,
    Response,
)

from starlette.background import BackgroundTask
from RTN import Torrent

from comet.debrid.manager import getDebrid
from comet.utils.general import (
    config_check,
    get_debrid_extension,
    get_indexer_manager,
    get_zilean,
    get_torrentio,
    filter,
    get_torrent_hash,
    translate,
    get_balanced_hashes,
    format_title, add_uncached_files, get_localized_titles, get_language_codes, get_client_ip,
    language_to_country_code
)
from comet.utils.logger import logger
from comet.utils.models import database, rtn, settings

streams = APIRouter(prefix=f"{settings.URL_PREFIX}")


@streams.get("/stream/{type}/{id}.json")
@streams.get("/{b64config}/stream/{type}/{id}.json")
async def stream(request: Request, b64config: str, type: str, id: str):
    config = config_check(b64config)
    if not config:
        return {
            "streams": [
                {
                    "name": "[⚠️] Comet",
                    "title": "Invalid Comet config.",
                    "url": "https://comet.fast",
                }
            ]
        }

    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        full_id = id
        season = None
        episode = None
        if type == "series":
            info = id.split(":")
            id = info[0]
            season = int(info[1])
            episode = int(info[2])

        try:
            kitsu = False
            if id == "kitsu":
                kitsu = True
                get_metadata = await session.get(
                    f"https://kitsu.io/api/edge/anime/{season}"
                )
                metadata = await get_metadata.json()
                name = metadata["data"]["attributes"]["canonicalTitle"]
                titles_per_language = {'default': name}
                season = 1
                year = None
            else:
                get_metadata = await session.get(
                    f"https://v3.sg.media-imdb.com/suggestion/a/{id}.json"
                )
                metadata = await get_metadata.json()
                element = metadata["d"][
                    0
                    if metadata["d"][0]["id"]
                    not in ["/imdbpicks/summer-watch-guide", "/emmys"]
                    else 1
                ]

                for element in metadata["d"]:
                    if "/" not in element["id"]:
                        break

                name = element["l"]
                year = element["y"]
                titles_per_language = {}
                if config.get('searchLanguage') and config['searchLanguage']:
                    language_codes = get_language_codes(config['searchLanguage'])
                    country_codes = language_to_country_code(language_codes)
                    titles_per_language = await get_localized_titles(language_codes, country_codes, id, session)
                titles_per_language['default'] = name
        except Exception as e:
            logger.warning(f"Exception while getting metadata for {id}: {e}")

            return {
                "streams": [
                    {
                        "name": "[⚠️] Comet",
                        "title": f"Can't get metadata for {id}",
                        "url": "https://comet.fast",
                    }
                ]
            }
        # Remove duplicate titles
        titles_per_language = {lang: translate(name) for lang, name in titles_per_language.items()}
        titles_per_language_list = list({title.lower(): title for title in titles_per_language.values()}.values())

        name_imdb = titles_per_language.get('default')
        log_name = name_imdb
        if type == "series":
            log_name = f"{name_imdb} S0{season}E0{episode}"

        cache_key = hashlib.md5(
            json.dumps(
                {
                    "debridService": config["debridService"],
                    "name": name_imdb,
                    "season": season,
                    "episode": episode,
                    "indexers": config["indexers"],
                }
            ).encode("utf-8")
        ).hexdigest()
        cached = await database.fetch_one(
            f"SELECT EXISTS (SELECT 1 FROM cache WHERE cacheKey = '{cache_key}')"
        )
        if cached[0] != 0:
            logger.info(f"Cache found for {log_name}")

            timestamp = await database.fetch_one(
                f"SELECT timestamp FROM cache WHERE cacheKey = '{cache_key}'"
            )
            if timestamp[0] + settings.CACHE_TTL < time.time():
                await database.execute(
                    f"DELETE FROM cache WHERE cacheKey = '{cache_key}'"
                )

                logger.info(f"Cache expired for {log_name}")

                # Deletes torrents matching cachekey without torrentid and after UNCACHED_TTL the ones with a torrentid
                expiration_timestamp = int(time.time()) - settings.UNCACHED_TTL
                await database.execute(
                    """
                    DELETE FROM uncached_torrents
                    WHERE cacheKey = :cache_key AND 
                          (
                            (torrentId IS NULL OR TRIM(torrentId) = '')
                            OR 
                            (TRIM(torrentId) != '' AND timestamp < :expiration_timestamp)
                          )
                    """,
                    {"cache_key": cache_key, "expiration_timestamp": expiration_timestamp}
                )

                logger.info(f"Expired uncached torrents removed for {log_name}")
            else:
                sorted_ranked_files = await database.fetch_one(
                    f"SELECT results FROM cache WHERE cacheKey = '{cache_key}'"
                )
                sorted_ranked_files = json.loads(sorted_ranked_files[0])

                debrid_extension = get_debrid_extension(config["debridService"])

                balanced_hashes = get_balanced_hashes(sorted_ranked_files, config, type)

                results = []
                if (
                    config["debridStreamProxyPassword"] != ""
                    and settings.PROXY_DEBRID_STREAM
                    and settings.PROXY_DEBRID_STREAM_PASSWORD
                    != config["debridStreamProxyPassword"]
                ):
                    results.append(
                        {
                            "name": "[⚠️] Comet",
                            "title": "Debrid Stream Proxy Password incorrect.\nStreams will not be proxied.",
                            "url": "https://comet.fast",
                        }
                    )
                results = []
                for resolution, hash_list in balanced_hashes.items():
                    for hash in hash_list:
                        if hash in sorted_ranked_files:
                            hash_data = sorted_ranked_files[hash]
                            data = hash_data["data"]
                            results.append(
                                {
                                    "name": f"[{debrid_extension}⚡] Comet {data['resolution']}",
                                    "title": format_title(data, config),
                                    "torrentTitle": (
                                        data["torrent_title"]
                                        if "torrent_title" in data
                                        else None
                                    ),
                                    "torrentSize": (
                                        data["torrent_size"]
                                        if "torrent_size" in data
                                        else None
                                    ),
                                    "url": f"{request.url.scheme}://{request.url.netloc}{f'{settings.URL_PREFIX}' if settings.URL_PREFIX else ''}/{b64config}/playback/{hash}/{data['index']}",
                                    "behaviorHints": {
                                        "filename": data["raw_title"],
                                        "bingeGroup": "comet|" + hash,
                                    }
                                }
                            )

                return {"streams": results}
        else:
            logger.info(f"No cache found for {log_name} with user configuration")

        if (
            settings.PROXY_DEBRID_STREAM
            and settings.PROXY_DEBRID_STREAM_PASSWORD
            == config["debridStreamProxyPassword"]
            and config["debridApiKey"] == ""
        ):
            config["debridService"] = (
                settings.PROXY_DEBRID_STREAM_DEBRID_DEFAULT_SERVICE
            )
            config["debridApiKey"] = settings.PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY

        debrid = getDebrid(session, config, get_client_ip(request))

        check_premium = await debrid.check_premium()
        if not check_premium:
            additional_info = ""
            if config["debridService"] == "alldebrid":
                additional_info = "\nCheck your email!"

            return {
                "streams": [
                    {
                        "name": "[⚠️] Comet",
                        "title": f"Invalid {config['debridService']} account.{additional_info}",
                        "url": "https://comet.fast",
                    }
                ]
            }

        indexer_manager_type = settings.INDEXER_MANAGER_TYPE

        search_indexer = len(config["indexers"]) != 0
        torrents = []
        tasks = []
        logger.info(
            f"Titles gathered for searching {titles_per_language}"
        )
        if indexer_manager_type and search_indexer:
            logger.info(
                f"Start of {indexer_manager_type} search for {log_name} with indexers {config['indexers']}"
            )

            search_terms = titles_per_language_list
            if type == "series":
                series_search_terms = []
                for titles in titles_per_language_list:
                    if not kitsu:
                        series_search_terms.append(f"{titles} S0{season}E0{episode}")
                    else:
                        series_search_terms.append(f"{titles} {episode}")
                search_terms.extend(series_search_terms)
            search_terms = list(dict.fromkeys(term.replace('-', ' ').replace('_', ' ') for term in reversed(search_terms)))[::-1]
            tasks.extend(
                get_indexer_manager(
                    session, indexer_manager_type, config["indexers"], term
                )
                for term in search_terms
            )
        else:
            logger.info(
                f"No indexer {'manager ' if not indexer_manager_type else ''}{'selected by user' if indexer_manager_type else 'defined'} for {log_name}"
            )

        titles_per_language_list = list(dict.fromkeys(title.replace('-', ' ').replace('_', ' ') for title in reversed(titles_per_language_list)))[::-1]
        if settings.ZILEAN_URL and 'z' in config["scrapingPreference"]:
            tasks.extend(
                get_zilean(session, titles, log_name, season, episode)
                for titles in titles_per_language_list
            )

        if settings.SCRAPE_TORRENTIO and 't' in config["scrapingPreference"]:
            tasks.append(get_torrentio(log_name, type, full_id))

        if settings.DEBRID_TAKE_FIRST > 0:
            if config["debridService"] == "debridlink" or config["debridService"] == "realdebrid":
                tasks.append(debrid.get_first_files(settings.DEBRID_TAKE_FIRST))

        search_response = await asyncio.gather(*tasks)
        for results in search_response:
            for result in results:
                torrents.append(result)

        logger.info(
            f"{len(torrents)} torrents found for {log_name}"
            + (
                " with "
                + ", ".join(
                    part
                    for part in [
                        indexer_manager_type,
                        "Zilean" if settings.ZILEAN_URL else None,
                        "Torrentio" if settings.SCRAPE_TORRENTIO else None,
                    ]
                    if part
                )
                if any(
                    [
                        indexer_manager_type,
                        settings.ZILEAN_URL,
                        settings.SCRAPE_TORRENTIO,
                    ]
                )
                else ""
            )
        )

        if len(torrents) == 0:
            return {"streams": []}

        if settings.TITLE_MATCH_CHECK:
            indexed_torrents = [(i, torrents[i]["Title"]) for i in range(len(torrents))]
            chunk_size = 50
            chunks = [
                indexed_torrents[i : i + chunk_size]
                for i in range(0, len(indexed_torrents), chunk_size)
            ]

            tasks = []
            for chunk in chunks:
                tasks.append(filter(chunk, titles_per_language_list, year))


            filtered_torrents = await asyncio.gather(*tasks)
            index_less = 0
            for result in filtered_torrents:
                for filtered in result:
                    if not filtered[1]:
                        del torrents[filtered[0] - index_less]
                        index_less += 1
                        continue

            logger.info(
                f"{len(torrents)} torrents passed title match check for {log_name}"
            )

            if len(torrents) == 0:
                return {"streams": []}

        tasks = []
        for i in range(len(torrents)):
            tasks.append(get_torrent_hash(session, (i, torrents[i])))

        torrent_hashes = await asyncio.gather(*tasks)
        index_less = 0
        for hash in torrent_hashes:
            if not hash[1]:
                del torrents[hash[0] - index_less]
                index_less += 1
                continue

            torrents[hash[0] - index_less]["InfoHash"] = hash[1]

        logger.info(f"{len(torrents)} info hashes found for {log_name}")

        if len(torrents) == 0:
            return {"streams": []}

        torrents_by_hash = {torrent['InfoHash']: torrent for torrent in torrents if torrent['InfoHash'] is not None}
        files = await debrid.get_files(
            torrents_by_hash,
            type,
            season,
            episode,
            kitsu,
        )
        logger.info(
            f"{len(files)} cached files found on {config.get('debridService', '?')} for {log_name}"
        )
        # Adds Uncached Files to files, based on config and cached results
        allowed_tracker_ids = config.get('indexersUncached', [])
        if allowed_tracker_ids:
            await add_uncached_files(files, torrents, cache_key, log_name, allowed_tracker_ids, database)

        ranked_files = dict()
        for hash in files:
            try:
                ranked_file = rtn.rank(
                    files[hash]["title"],
                    hash,  # , correct_title=name, remove_trash=True
                )

                ranked_files[hash] = ranked_file
            except:
                pass

        len_ranked_files = len(ranked_files)
        logger.info(
            f"{len_ranked_files} cached files found on {config['debridService']} for {log_name}"
        )

        if len_ranked_files == 0:
            return {"streams": []}

        sorted_ranked_files = {
            key: (value.model_dump() if isinstance(value, Torrent) else value)
            for key, value in ranked_files.items()
        }

        logger.info(
            f"{len(sorted_ranked_files)} cached files found on {config['debridService']} for {log_name}"
        )

        for hash in sorted_ranked_files:  # needed for caching
            sorted_ranked_files[hash]["data"]["title"] = files[hash]["title"]
            sorted_ranked_files[hash]["data"]["torrent_title"] = torrents_by_hash[hash]["Title"]
            sorted_ranked_files[hash]["data"]["tracker"] = torrents_by_hash[hash]["Tracker"]
            sorted_ranked_files[hash]["data"]["size"] = files[hash]["size"]
            sorted_ranked_files[hash]["data"]["uncached"] = files[hash]["uncached"]
            if files[hash].get("complete"):
                sorted_ranked_files[hash]["data"]["complete"] = files[hash]["complete"]
            if torrents_by_hash[hash].get("Seeders"):
                sorted_ranked_files[hash]["data"]["seeders"] = torrents_by_hash[hash].get("Seeders")
            torrent_size = torrents_by_hash[hash]["Size"]
            sorted_ranked_files[hash]["data"]["torrent_size"] = (
                torrent_size if torrent_size else files[hash]["size"]
            )
            sorted_ranked_files[hash]["data"]["index"] = files[hash]["index"]

        json_data = json.dumps(sorted_ranked_files).replace("'", "''")
        await database.execute(
            f"INSERT {'OR IGNORE ' if settings.DATABASE_TYPE == 'sqlite' else ''}INTO cache (cacheKey, results, timestamp) VALUES (:cache_key, :json_data, :timestamp){' ON CONFLICT DO NOTHING' if settings.DATABASE_TYPE == 'postgresql' else ''}",
            {"cache_key": cache_key, "json_data": json_data, "timestamp": time.time()},
        )
        logger.info(f"Results have been cached for {log_name}")

        debrid_extension = get_debrid_extension(config["debridService"])

        balanced_hashes = get_balanced_hashes(sorted_ranked_files, config, type)

        results = []
        if (
            config["debridStreamProxyPassword"] != ""
            and settings.PROXY_DEBRID_STREAM
            and settings.PROXY_DEBRID_STREAM_PASSWORD
            != config["debridStreamProxyPassword"]
        ):
            results.append(
                {
                    "name": "[⚠️] Comet",
                    "title": "Debrid Stream Proxy Password incorrect.\nStreams will not be proxied.",
                    "url": "https://comet.fast",
                }
            )

        results = []
        for resolution, hash_list in balanced_hashes.items():
            for hash in hash_list:
                if hash in sorted_ranked_files:
                    hash_data = sorted_ranked_files[hash]
                    data = hash_data["data"]
                    results.append(
                        {
                            "name": f"[{debrid_extension}⚡] Comet {data['resolution']}",
                            "title": format_title(data, config),
                            "torrentTitle": data["torrent_title"],
                            "torrentSize": data["torrent_size"],
                            "url": f"{request.url.scheme}://{request.url.netloc}{f'{settings.URL_PREFIX}' if settings.URL_PREFIX else ''}/{b64config}/playback/{hash}/{data['index']}",
                            "behaviorHints": {
                                "filename": data["raw_title"],
                                "bingeGroup": "comet|" + hash,
                            }
                        }
                    )
        return {"streams": results}


@streams.head("/{b64config}/playback/{hash}/{index}")
async def playback(b64config: str, hash: str, index: str):
    return RedirectResponse("https://stremio.fast", status_code=302)


class CustomORJSONResponse(Response):
    media_type = "application/json"

    def render(self, content) -> bytes:
        assert orjson is not None, "orjson must be installed"
        return orjson.dumps(content, option=orjson.OPT_INDENT_2)


@streams.get("/active-connections", response_class=CustomORJSONResponse)
async def active_connections(request: Request, password: str):
    if password != settings.DASHBOARD_ADMIN_PASSWORD:
        return "Invalid Password"

    active_connections = await database.fetch_all("SELECT * FROM active_connections")

    return {
        "total_connections": len(active_connections),
        "active_connections": active_connections,
    }


@streams.get("/{b64config}/playback/{hash}/{index}")
async def playback(request: Request, b64config: str, hash: str, index: str):
    config = config_check(b64config)
    base_url = str(request.base_url).rstrip('/')
    index = index.split('.', 1)[0]
    if not config:
        return RedirectResponse(f"{base_url}{f'{settings.URL_PREFIX}' if settings.URL_PREFIX else ''}/assets/invalidconfig.mp4", status_code=302)

    if (
        settings.PROXY_DEBRID_STREAM
        and settings.PROXY_DEBRID_STREAM_PASSWORD == config["debridStreamProxyPassword"]
        and config["debridApiKey"] == ""
    ):
        config["debridService"] = settings.PROXY_DEBRID_STREAM_DEBRID_DEFAULT_SERVICE
        config["debridApiKey"] = settings.PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY

    async with aiohttp.ClientSession() as session:
        # Check for cached download link
        cached_link = await database.fetch_one(
            f"SELECT link, timestamp FROM download_links WHERE debrid_key = '{config['debridApiKey']}' AND hash = '{hash}' AND file_index = '{index}'"
        )

        current_time = time.time()
        download_link = None
        if cached_link:
            link = cached_link["link"]
            timestamp = cached_link["timestamp"]

            if current_time - timestamp < 3600:
                download_link = link
            else:
                # Cache expired, remove old entry
                await database.execute(
                    f"DELETE FROM download_links WHERE debrid_key = '{config['debridApiKey']}' AND hash = '{hash}' AND file_index = '{index}'"
                )

        ip = get_client_ip(request)
        if not download_link:
            debrid = getDebrid(session, config, ip)
            download_link = await debrid.generate_download_link(hash, index)

            if not download_link:
                return RedirectResponse(f"{base_url}{f'{settings.URL_PREFIX}' if settings.URL_PREFIX else ''}/assets/uncached.mp4", status_code=302)
            # Cleanup uncached Torrent from db if possible
            await database.execute(
                "DELETE FROM uncached_torrents WHERE hash = :hash",
                {"hash": hash}
            )
            # Cache the new download link
            await database.execute(
                f"INSERT {'OR IGNORE ' if settings.DATABASE_TYPE == 'sqlite' else ''}INTO download_links (debrid_key, hash, file_index, link, timestamp) VALUES (:debrid_key, :hash, :file_index, :link, :timestamp){' ON CONFLICT DO NOTHING' if settings.DATABASE_TYPE == 'postgresql' else ''}",
                {
                    "debrid_key": config["debridApiKey"],
                    "hash": hash,
                    "file_index": index,
                    "link": download_link,
                    "timestamp": current_time,
                },
            )

        if (
            settings.PROXY_DEBRID_STREAM
            and settings.PROXY_DEBRID_STREAM_PASSWORD
            == config["debridStreamProxyPassword"]
        ):
            active_ip_connections = await database.fetch_all(
                "SELECT ip, COUNT(*) as connections FROM active_connections GROUP BY ip"
            )
            if any(
                connection["ip"] == ip
                and connection["connections"]
                >= settings.PROXY_DEBRID_STREAM_MAX_CONNECTIONS
                for connection in active_ip_connections
            ):
                return RedirectResponse(f"{base_url}{f'{settings.URL_PREFIX}' if settings.URL_PREFIX else ''}/assets/proxylimit.mp4", status_code=302)

            proxy = None

            class Streamer:
                def __init__(self, id: str):
                    self.id = id

                    self.client = httpx.AsyncClient(proxy=proxy)
                    self.response = None

                async def stream_content(self, headers: dict):
                    async with self.client.stream(
                        "GET", download_link, headers=headers
                    ) as self.response:
                        async for chunk in self.response.aiter_raw():
                            yield chunk

                async def close(self):
                    await database.execute(
                        f"DELETE FROM active_connections WHERE id = '{self.id}'"
                    )

                    if self.response is not None:
                        await self.response.aclose()
                    if self.client is not None:
                        await self.client.aclose()

            range_header = request.headers.get("range", "bytes=0-")

            response = await session.head(
                download_link, headers={"Range": range_header}
            )
            if response.status == 503 and config["debridService"] == "alldebrid":
                proxy = (
                    settings.DEBRID_PROXY_URL
                )  # proxy is not needed to proxy realdebrid stream

                response = await session.head(
                    download_link, headers={"Range": range_header}, proxy=proxy
                )

            if response.status == 206:
                id = str(uuid.uuid4())
                await database.execute(
                    f"INSERT  {'OR IGNORE ' if settings.DATABASE_TYPE == 'sqlite' else ''}INTO active_connections (id, ip, content, timestamp) VALUES (:id, :ip, :content, :timestamp){' ON CONFLICT DO NOTHING' if settings.DATABASE_TYPE == 'postgresql' else ''}",
                    {
                        "id": id,
                        "ip": ip,
                        "content": str(response.url),
                        "timestamp": current_time,
                    },
                )

                streamer = Streamer(id)

                return StreamingResponse(
                    streamer.stream_content({"Range": range_header}),
                    status_code=206,
                    headers={
                        "Content-Range": response.headers["Content-Range"],
                        "Content-Length": response.headers["Content-Length"],
                        "Accept-Ranges": "bytes",
                    },
                    background=BackgroundTask(streamer.close),
                )

            return RedirectResponse(f"{base_url}{f'{settings.URL_PREFIX}' if settings.URL_PREFIX else ''}/assets/uncached.mp4", status_code=302)

        return RedirectResponse(download_link, status_code=302)


@streams.get("/assets/{filename}")
async def stream_file(filename: str, range: str = Header(None)):
    async def file_response(file_path: str, range_header: str = None):
        file_size = os.path.getsize(file_path)
        start = 0
        end = file_size - 1

        if range_header:
            start, end = range_header.replace("bytes=", "").split("-")
            start = int(start)
            end = int(end) if end else file_size - 1

        chunk_size = 1024 * 1024  # 1MB chunks
        headers = {
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Accept-Ranges": "bytes",
            "Content-Type": "video/mp4",
            "Content-Length": str(end - start + 1),
        }

        async def file_iterator():
            with open(file_path, "rb") as video:
                video.seek(start)
                while True:
                    chunk = video.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

        return StreamingResponse(file_iterator(), status_code=206 if range_header else 200, headers=headers)

    file_path = f"comet/assets/{filename}"
    return await file_response(file_path, range)
