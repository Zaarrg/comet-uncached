import asyncio
import datetime
import hashlib
import time
import uuid
from collections import defaultdict
from urllib.parse import quote, unquote

import PTT
import aiohttp
import httpx

import orjson

from fastapi import APIRouter, Request, BackgroundTasks
from fastapi.responses import (
    RedirectResponse,
    StreamingResponse,
    Response,
)

from starlette.background import BackgroundTask
from RTN import Torrent, sort_torrents, parse
from starlette.responses import FileResponse

from comet.debrid.manager import getDebrid
from comet.utils.general import (
    config_check,
    get_debrid_extension,
    get_indexer_manager,
    get_zilean,
    get_torrentio,
    get_mediafusion,
    filter,
    get_torrent_hash,
    translate,
    get_balanced_hashes,
    format_title, add_uncached_files, get_localized_titles, get_language_codes, get_client_ip,
    language_to_country_code, check_completion, short_encrypt,
    add_torrent_to_cache, update_uncached_status, derive_debrid_key, search_imdb_id, is_video, clean_titles,
    catalog_config, build_custom_filename, generate_unified_streams, cache_download_link, debrid_services
)
from comet.utils.logger import logger
from comet.utils.models import database, rtn, settings, trackers

streams = APIRouter(prefix=f"{settings.URL_PREFIX}")


@streams.get("/stream/{type}/{id}.json")
async def stream_noconfig(request: Request, type: str, id: str):
    return {
        "streams": [
            {
                "name": "[⚠️] Comet",
                "description": f"{request.url.scheme}://{request.url.netloc}/configure",
                "url": "https://comet.fast",
            }
        ]
    }


@streams.get("/{b64config}/catalog/other/{id}.json")
async def stream(
        request: Request,
        b64config: str,
):
    config = config_check(b64config)
    if not config:
        return {
            "metas": [
                {
                    "id": "comet-" + config["debridService"],
                    "type": "other",
                    "name": "[⚠️] Comet Invalid Comet config.",
                    "description": "The provided config is invalid. Try reinstalling your addon.",
                }
            ],
            "cacheMaxAge": 0
        }

    if config["debridService"] not in catalog_config:
        return {
            "metas": [
                {
                    "id": "comet-" + config["debridService"],
                    "type": "other",
                    "name": "[⚠️] Comet Provider not Supported.",
                    "description": "Debrid Provider is not Supported. Only Debrid-Link, Real-Debrid and All-Debrid.",
                }
            ],
            "cacheMaxAge": 0
        }

    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(
            connector=connector, raise_for_status=True
    ) as session:
        debrid = getDebrid(session, config, get_client_ip(request))
        debrid_config = catalog_config[config["debridService"]]
        debrid_filter = debrid_config["preview_filter"]

        files = await debrid.get_first_files(debrid_config["amount"]) if config["debridService"] != "torbox" else await debrid.get_first_files(debrid_config["amount"], "all")
        filter_files = debrid_filter(files)

        # Group files by cleaned title with error handling
        title_groups = {}

        for idx, file in enumerate(filter_files):
            try:
                file["Title"] = unquote(file["Title"])
                parsed = parse(file["Title"])
                clean_title = clean_titles(parsed.parsed_title)
            except Exception as e:
                clean_title = f"error_{idx}"  # Unique key for failed parses

            if clean_title not in title_groups:
                title_groups[clean_title] = {
                    'files': [],
                    'original_indexes': []
                }
            title_groups[clean_title]['files'].append(file)
            title_groups[clean_title]['original_indexes'].append(idx)

        # Batch fetch unique valid titles
        max_concurrent = 30
        semaphore = asyncio.Semaphore(max_concurrent)

        async def fetch_imdb(clean_title):
            if clean_title.startswith("error_"):
                return None  # Skip failed parses
            async with semaphore:
                try:
                    return await search_imdb_id(clean_title, session)
                except Exception as e:
                    return None

        unique_titles = [t for t in title_groups.keys() if not t.startswith("error_")]
        imdb_results = await asyncio.gather(*[fetch_imdb(t) for t in unique_titles])
        title_to_imdb = dict(zip(unique_titles, imdb_results))

        # Build results with all original files
        metas_list = [None] * len(filter_files)

        for clean_title, group_data in title_groups.items():
            # Get IMDb data for valid titles
            imdb_data = title_to_imdb.get(clean_title) if not clean_title.startswith("error_") else None

            # Create metadata template
            meta_template = {}
            if imdb_data:
                meta_template = {
                    "description": imdb_data.get("description"),
                    "genres": imdb_data.get("genres"),
                    "poster": f"https://images.metahub.space/poster/medium/{imdb_data['id']}/img",
                    "background": f"https://images.metahub.space/background/medium/{imdb_data['id']}/img",
                    "logo": f"https://images.metahub.space/logo/medium/{imdb_data['id']}/img",
                    "imdbRating": imdb_data.get("imdbRating"),
                    "releaseInfo": f"{imdb_data.get('startYear', '')}-{imdb_data.get('endYear', '')}",
                }
                # Remove empty fields
                meta_template = {k: v for k, v in meta_template.items() if v not in (None, "")}

            # Apply to all files in group
            for file, orig_idx in zip(group_data['files'], group_data['original_indexes']):
                metas_list[orig_idx] = {
                    "id": f"comet-{config['debridService']}-{file['Id']}",
                    "type": "other",
                    "name": file["Title"],
                    **meta_template  # Only adds populated fields
                }

        return {
            "metas": [m for m in metas_list if m is not None],  # Just in case
            "cacheMaxAge": 0
        }


@streams.get("/{b64config}/meta/other/{id}.json")
async def stream(
        request: Request,
        b64config: str,
        id: str,
):
    config = config_check(b64config)
    if not config:
        return {
            "metas": [
                {
                    "id": "comet-" + config["debridService"],
                    "type": "other",
                    "name": "[⚠️] Comet Invalid Comet config.",
                    "description": "Invalid Comet config.",
                }
            ],
            "cacheMaxAge": 0
        }

    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(
            connector=connector, raise_for_status=True
    ) as session:
        debrid = getDebrid(session, config, get_client_ip(request))
        debrid_id = id.split("-")[-1]

        if config.get("debridService") == "torbox":
            torrent = await debrid.get_info(debrid_id, "torrent")
            if not torrent:
                torrent = await debrid.get_info(debrid_id, "usenet")
        else:
            torrent = await debrid.get_info(debrid_id)

        debrid_config = catalog_config[config["debridService"]]
        debrid_meta_filter = debrid_config["meta_filter"]
        debrid_file_getter = debrid_config["files_getter"]
        debrid_title_getter = debrid_config["title_getter"]
        debrid_torrent_id_getter = debrid_config["torrent_id_getter"]
        debrid_hash_getter = debrid_config["hash_getter"]

        debrid_file_id_getter = debrid_config["file_id_getter"]
        debrid_file_name_getter = debrid_config["file_name_getter"]

        files = debrid_file_getter(torrent)
        files = debrid_meta_filter(files)

        filename = debrid_title_getter(torrent)
        filename = unquote(filename)
        torrent_id = debrid_torrent_id_getter(torrent)
        info_hash = debrid_hash_getter(torrent)
        parsed_data = parse(filename)

        imdb_data = await search_imdb_id(clean_titles(parsed_data.parsed_title), session)

        short_config = b64config
        if settings.TOKEN:
            short_config = {
                "debridApiKey": config["debridApiKey"],
                "debridStreamProxyPassword": config["debridStreamProxyPassword"],
                "debridService": config["debridService"]
            }
            short_config = short_encrypt(orjson.dumps(short_config).decode("utf-8"), settings.TOKEN)

        videos = []
        for i, file in enumerate(files):
            file_id = debrid_file_id_getter(file, i)
            file_name = debrid_file_name_getter(file)
            file_name = unquote(file_name)

            url_friendly_file = quote(file_name.replace('/', '-'), safe='')
            parsed_data = parse(file_name)
            binge_filename = build_custom_filename(vars(parsed_data))
            binge_hash = hashlib.sha1(binge_filename.encode('utf-8')).hexdigest()
            video_data = {
                "id": f"comet-{config['debridService']}-{file_id}",
                "title": file_name,
                "streams": [
                    {
                        "url": f"{request.url.scheme}://{request.url.netloc}{f'{settings.URL_PREFIX}' if settings.URL_PREFIX else ''}/{short_config}/playback/{info_hash}-{torrent_id}/{file_id}/{url_friendly_file}",
                        "behaviorHints": {
                            "filename": file_name,
                            "bingeGroup": "comet|" + binge_hash,
                        },
                    }
                ],
            }
            if parsed_data.seasons:
                video_data["season"] = parsed_data.seasons[0]
            if parsed_data.episodes:
                video_data["episode"] = parsed_data.episodes[0]

            if imdb_data and video_data.get("episode"):
                season = video_data.get("season", 1)
                video_data["thumbnail"] = f"https://episodes.metahub.space/{imdb_data['id']}/{season}/{video_data['episode']}/w780.jpg"

            if imdb_data and not video_data.get("thumbnail", None):
                video_data["thumbnail"] = f"https://images.metahub.space/background/small/{imdb_data['id']}/img"

            videos.append(video_data)

        # Sort stuff that are not episodes like samples to the beginning to show them at the end in stremio ui
        videos.sort(key=lambda video: (video.get("episode") is not None, -int(video["episode"]) if "episode" in video else 0))

        meta_data = {
            "id": f"comet-{config['debridService']}-{torrent_id}",
            "type": "other",
            "name": filename,
            "infoHash": info_hash,
            "videos": videos,
        }

        if imdb_data:
            meta_data["description"] = imdb_data["description"]
            meta_data["imdbRating"] = imdb_data["imdbRating"]
            meta_data["genres"] = imdb_data["genres"]
            meta_data["releaseInfo"] = f"{imdb_data['startYear']}-{imdb_data['endYear']}"
            meta_data["logo"] = f"https://images.metahub.space/logo/medium/{imdb_data['id']}/img"
            meta_data["poster"] = f"https://images.metahub.space/poster/medium/{imdb_data['id']}/img"
            meta_data["background"] = f"https://images.metahub.space/background/medium/{imdb_data['id']}/img"

        result = {
            "meta": meta_data,
            "cacheMaxAge": 0
        }

        return result


@streams.get("/{b64config}/stream/{type}/{id}.json")
async def stream(
    request: Request,
    b64config: str,
    type: str,
    id: str,
    background_tasks: BackgroundTasks,
):
    config = config_check(b64config)
    if not config:
        return {
            "streams": [
                {
                    "name": "[⚠️] Comet",
                    "description": "Invalid Comet config.",
                    "url": "https://comet.fast",
                }
            ]
        }

    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(
        connector=connector, raise_for_status=True
    ) as session:
        full_id = id
        season = None
        episode = None
        if type == "series":
            info = id.split(":")
            id = info[0]
            season = int(info[1])
            episode = int(info[2])

        year = None
        year_end = None
        try:
            kitsu = False
            if id == "kitsu":
                kitsu = True
                get_metadata = await session.get(
                    f"https://kitsu.io/api/edge/anime/{season}"
                )
                metadata = await get_metadata.json()
                name = metadata["data"]["attributes"]["canonicalTitle"]
                search_titles = {'default': name}
                season = 1
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
                year = element.get("y")
                if "yr" in element:
                    year_end = int(element["yr"].split("-")[1])

                search_titles = {'default': name}
        except Exception as e:
            logger.warning(f"Exception while getting metadata for {id}: {e}")

            return {
                "streams": [
                    {
                        "name": "[⚠️] Comet",
                        "description": f"Can't get metadata for {id}",
                        "url": "https://comet.fast",
                    }
                ]
            }
        # Get aliases
        language_codes = get_language_codes([language for language in PTT.parse.LANGUAGES_TRANSLATION_TABLE.values()])
        country_codes = language_to_country_code(language_codes)
        aliases = await get_localized_titles(language_codes, country_codes, id, session)

        # Get Language Codes for searching
        search_language_codes = get_language_codes(config['searchLanguage'])
        search_country_codes = language_to_country_code(search_language_codes)
        search_filtered_aliases = {k: v for k, v in aliases.items() if k in search_language_codes + search_country_codes}
        search_titles = search_titles | search_filtered_aliases

        # Remove duplicate titles
        search_titles = {lang: translate(name) for lang, name in search_titles.items()}
        search_titles_list = list({title.lower(): title for title in search_titles.values()}.values())

        name_imdb = search_titles.get('default')
        log_name = name_imdb
        if type == "series":
            log_name = f"{name} S{season:02d}E{episode:02d}"

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

        if config["debridApiKey"] == "":
            services = ["realdebrid", "alldebrid", "premiumize", "torbox", "debridlink"]
            debrid_emoji = "⬇️"
        else:
            services = [config["debridService"]]
            debrid_emoji = "⚡"

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
                    "description": "Debrid Stream Proxy Password incorrect.\nStreams will not be proxied.",
                    "url": "https://comet.fast",
                }
            )

        indexers = config["indexers"].copy()
        if settings.SCRAPE_TORRENTIO:
            indexers.append("torrentio")
        if settings.SCRAPE_MEDIAFUSION:
            indexers.append("mediafusion")
        if settings.ZILEAN_URL:
            indexers.append("dmm")
        if settings.DEBRID_TAKE_FIRST > 0:
            indexers.append(config["debridService"])

        indexers_json = orjson.dumps(indexers).decode("utf-8")
        all_sorted_ranked_files = {}
        trackers_found = (
            set()
        )  # we want to check that we have a cache for each of the user's trackers
        the_time = time.time()
        cache_ttl = settings.CACHE_TTL

        for debrid_service in services:
            cached_results = await database.fetch_all(
                f"""
                    SELECT info_hash, tracker, data
                    FROM cache
                    WHERE debridService = :debrid_service
                    AND name = :name
                    AND ((cast(:season as INTEGER) IS NULL AND season IS NULL) OR season = cast(:season as INTEGER))
                    AND ((cast(:episode as INTEGER) IS NULL AND episode IS NULL) OR episode = cast(:episode as INTEGER))
                    AND tracker IN (SELECT cast(value as TEXT) FROM {'json_array_elements_text' if settings.DATABASE_TYPE == 'postgresql' else 'json_each'}(:indexers))
                    AND timestamp + :cache_ttl >= :current_time
                """,
                {
                    "debrid_service": debrid_service,
                    "name": name,
                    "season": season,
                    "episode": episode,
                    "indexers": indexers_json,
                    "cache_ttl": cache_ttl,
                    "current_time": the_time,
                },
            )



            for result in cached_results:
                trackers_found.add(result["tracker"].lower())

                hash = result["info_hash"]
                if "searched" in hash:
                    continue

                all_sorted_ranked_files[hash] = orjson.loads(result["data"])

        if len(all_sorted_ranked_files) != 0 and set(indexers).issubset(trackers_found):
            debrid_extension = get_debrid_extension(
                debrid_service, config["debridApiKey"]
            )

            balanced_hashes = get_balanced_hashes(all_sorted_ranked_files, config, type)

            results = generate_unified_streams(
                request=request,
                config=config,
                b64config=b64config,
                binge_preference=settings.BINGE_PREFERENCE,
                sorted_files=all_sorted_ranked_files,
                balanced_hashes=balanced_hashes,
                debrid_extension=debrid_extension,
                trackers=trackers,
                is_cached=True,
                debrid_emoji=debrid_emoji
            )

            logger.info(
                f"{len(all_sorted_ranked_files)} cached results found for {log_name}"
            )

            return {"streams": results}

        if config["debridApiKey"] == "":
            return {
                "streams": [
                    {
                        "name": "[⚠️] Comet",
                        "description": "No cache found for Direct Torrenting.",
                        "url": "https://comet.fast",
                    }
                ]
            }
        logger.info(f"No cache found for {log_name} with user configuration")

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
                        "description": f"Invalid {config['debridService']} account.{additional_info}",
                        "url": "https://comet.fast",
                    }
                ]
            }

        indexer_manager_type = settings.INDEXER_MANAGER_TYPE

        search_indexer = len(config["indexers"]) != 0
        torrents = []
        tasks = []
        logger.info(
            f"Titles gathered for searching {search_titles}"
        )
        if indexer_manager_type and search_indexer:
            logger.info(
                f"Start of {indexer_manager_type} search for {log_name} with indexers {config['indexers']}"
            )

            search_terms = search_titles_list
            if type == "series":
                series_search_terms = []
                for titles in search_titles_list:
                    if not kitsu:
                        series_search_terms.append(f"{name} S{season:02d}E{episode:02d}")
                    else:
                        series_search_terms.append(f"{name} {episode}")
                search_terms.extend(series_search_terms)
            search_terms = list(dict.fromkeys(term.replace('-', ' ').replace('_', ' ') for term in reversed(search_terms)))[::-1]
            tasks.extend(
                get_indexer_manager(
                    session, indexer_manager_type, config["indexers"], term, config
                )
                for term in search_terms
            )
        else:
            logger.info(
                f"No indexer {'manager ' if not indexer_manager_type else ''}{'selected by user' if indexer_manager_type else 'defined'} for {log_name}"
            )

        search_titles_list = list(dict.fromkeys(title.replace('-', ' ').replace('_', ' ') for title in reversed(search_titles_list)))[::-1]
        if settings.ZILEAN_URL and 'z' in config["scrapingPreference"]:
            tasks.extend(
                get_zilean(session, titles, log_name, season, episode)
                for titles in search_titles_list
            )

        if settings.SCRAPE_TORRENTIO and 't' in config["scrapingPreference"]:
            tasks.append(get_torrentio(log_name, type, full_id))
        # Services Supported by get_first_files has to match "tracker" returned by get_first_files and config["debridService"]
        if settings.DEBRID_TAKE_FIRST > 0:
            if config["debridService"] in debrid_services:
                tasks.append(debrid.get_first_files(settings.DEBRID_TAKE_FIRST))

        if settings.SCRAPE_MEDIAFUSION:
            tasks.append(get_mediafusion(log_name, type, full_id))

        search_response = await asyncio.gather(*tasks)
        # Split the search_response into debrid and non-debrid entries
        debrid_entries = []
        non_debrid_entries = []
        for results in search_response:
            for entry in results:
                if entry.get("Tracker") in debrid_services:
                    debrid_entries.append(entry)
                else:
                    non_debrid_entries.append(entry)

        # Process non-debrid entries first and track their InfoHashes
        hash_to_indices = defaultdict(list)
        torrents = []

        for idx, entry in enumerate(non_debrid_entries):
            torrents.append(entry)
            info_hash = entry["InfoHash"]
            hash_to_indices[info_hash].append(idx)

        # Process debrid entries to update existing trackers or add new entries
        for entry in debrid_entries:
            info_hash = entry["InfoHash"]
            if info_hash in hash_to_indices:
                # Update all non-debrid entries with the same hash
                for idx in hash_to_indices[info_hash]:
                    torrents[idx]["Tracker"] = entry["Tracker"]
            else:
                # Add the debrid entry if no existing entry
                torrents.append(entry)
                # Update the hash_to_indices to track the new entry
                hash_to_indices[info_hash].append(len(torrents) - 1)

        logger.info(
            f"{len(torrents)} unique torrents found for {log_name}"
            + (
                " with "
                + ", ".join(
                    part
                    for part in [
                        indexer_manager_type,
                        "Zilean" if settings.ZILEAN_URL else None,
                        "Torrentio" if settings.SCRAPE_TORRENTIO else None,
                        "MediaFusion" if settings.SCRAPE_MEDIAFUSION else None,
                    ]
                    if part
                )
                if any(
                    [
                        indexer_manager_type,
                        settings.ZILEAN_URL,
                        settings.SCRAPE_TORRENTIO,
                        settings.SCRAPE_MEDIAFUSION,
                    ]
                )
                else ""
            )
        )

        if len(torrents) == 0:
            return {"streams": []}

        if settings.TITLE_MATCH_CHECK:
            # Adjust aliases for RTN - Has to be key: list
            aliases = {k: [v] if isinstance(v, str) else v for k, v in aliases.items()}

            indexed_torrents = [(i, torrents[i]["Title"]) for i in range(len(torrents))]
            chunk_size = 50
            chunks = [
                indexed_torrents[i : i + chunk_size]
                for i in range(0, len(indexed_torrents), chunk_size)
            ]

            remove_adult_content = (
                settings.REMOVE_ADULT_CONTENT and config["removeTrash"]
            )
            tasks = []
            for chunk in chunks:
                tasks.append(
                    filter(chunk, search_titles_list, season, year, year_end, aliases, remove_adult_content)
                )

            filtered_torrents = await asyncio.gather(*tasks)

            # Collect indices of torrents that should be kept
            indices_to_keep = set()
            for result in filtered_torrents:
                for filtered in result:
                    if filtered[1]:  # Torrent passes the filter
                        indices_to_keep.add(filtered[0])

            # Rebuild the torrents list with only the kept indices
            torrents = [torrent for i, torrent in enumerate(torrents) if i in indices_to_keep]

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

        files = await debrid.get_files(
            list({hash[1] for hash in torrent_hashes if hash[1] is not None}),
            type,
            season,
            episode,
            kitsu
        )

        len_files = len(files)
        logger.info(
            f"{len_files} cached files found on {config['debridService']} for {log_name}"
        )

        # Adds Uncached Files to files, based on config and cached results
        allowed_tracker_ids = config.get('indexersUncached', [])
        if allowed_tracker_ids:
            await add_uncached_files(files, torrents, log_name, allowed_tracker_ids, season, episode, kitsu)

        ranked_files = set()
        torrents_by_hash = {torrent["InfoHash"]: torrent for torrent in torrents}
        for hash in files:
            try:
                ranked_file = rtn.rank(
                    torrents_by_hash[hash]["Title"],
                    hash,
                    remove_trash=False,  # user can choose if he wants to remove it
                )

                ranked_files.add(ranked_file)
            except Exception as e:
                logger.error(e)
                pass

        sorted_ranked_files = sort_torrents(ranked_files)

        len_sorted_ranked_files = len(sorted_ranked_files)

        if len_sorted_ranked_files == 0:
            return {"streams": []}

        sorted_ranked_files = {
            key: (value.model_dump() if isinstance(value, Torrent) else value)
            for key, value in sorted_ranked_files.items()
        }
        for hash in sorted_ranked_files:  # needed for caching
            sorted_ranked_files[hash]["data"]["title"] = files[hash]["title"]
            sorted_ranked_files[hash]["data"]["torrent_title"] = torrents_by_hash[hash]["Title"]
            sorted_ranked_files[hash]["data"]["tracker"] = torrents_by_hash[hash]["Tracker"]
            sorted_ranked_files[hash]["data"]["protocol"] = torrents_by_hash[hash].get("Protocol", "torrent")
            sorted_ranked_files[hash]["data"]["size"] = files[hash]["size"]
            sorted_ranked_files[hash]["data"]["uncached"] = files[hash]["uncached"]
            if files[hash].get("complete") is None:
                sorted_ranked_files[hash]["data"]["complete"] = sorted_ranked_files[hash]["data"]["complete"] or check_completion(sorted_ranked_files[hash]["data"]["raw_title"], season)
            if torrents_by_hash[hash].get("Seeders"):
                sorted_ranked_files[hash]["data"]["seeders"] = torrents_by_hash[hash].get("Seeders")

            sorted_ranked_files[hash]["data"]["torrent_id"] = ""
            sorted_ranked_files[hash]["data"]["container_id"] = ""
            sorted_ranked_files[hash]["data"]["link"] = torrents_by_hash[hash].get("Link", "")
            sorted_ranked_files[hash]["data"]["magnet"] = torrents_by_hash[hash].get("MagnetUri", "")

            torrent_size = torrents_by_hash[hash]["Size"]
            sorted_ranked_files[hash]["data"]["size"] = (
                files[hash]["size"]
            )
            sorted_ranked_files[hash]["data"]["torrent_size"] = (
                torrent_size if torrent_size else files[hash]["size"]
            )
            sorted_ranked_files[hash]["data"]["index"] = files[hash]["index"]

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
                    "description": "Debrid Stream Proxy Password incorrect.\nStreams will not be proxied.",
                    "url": "https://comet.fast",
                }
            )

        results = generate_unified_streams(
            request=request,
            config=config,
            b64config=b64config,
            binge_preference=settings.BINGE_PREFERENCE,
            sorted_files=sorted_ranked_files,
            balanced_hashes=balanced_hashes,
            debrid_extension=debrid_extension,
        )

        background_tasks.add_task(
            add_torrent_to_cache, config, name, season, episode, sorted_ranked_files, balanced_hashes
        )

        logger.info(f"Results have been cached for {log_name}")

        return {"streams": results}


@streams.head("/{b64config}/playback/{hash}/{index}/{file_name}")
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


@streams.get("/{b64config}/playback/{hash}/{index}/{file_name}")
async def playback(request: Request, b64config: str, hash: str, index: str):
    config = config_check(b64config)
    base_url = str(request.base_url).rstrip('/')
    index = index.split('.', 1)[0]
    if not config:
        return FileResponse("comet/assets/invalidconfig.mp4")

    hash_parts = hash.split('-', 1)
    hash = hash_parts[0]
    usenet_id = hash_parts[1] if len(hash_parts) > 1 else None

    if (
        settings.PROXY_DEBRID_STREAM
        and settings.PROXY_DEBRID_STREAM_PASSWORD == config["debridStreamProxyPassword"]
        and config["debridApiKey"] == ""
    ):
        config["debridService"] = settings.PROXY_DEBRID_STREAM_DEBRID_DEFAULT_SERVICE
        config["debridApiKey"] = settings.PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY

    async with aiohttp.ClientSession(raise_for_status=True) as session:
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
            debrid = getDebrid(
                session,
                config,
                ip
                if (
                    not settings.PROXY_DEBRID_STREAM
                    or settings.PROXY_DEBRID_STREAM_PASSWORD
                    != config["debridStreamProxyPassword"]
                )
                else "",
            )
            derived_key = derive_debrid_key(config["debridApiKey"])
            if config.get("debridService") == "torbox":
                download_link = await debrid.generate_download_link(hash, index, derived_key, usenet_id)
            else:
                download_link = await debrid.generate_download_link(hash, index, derived_key)

            if not download_link:
                return FileResponse("comet/assets/uncached.mp4")
            # Update uncached Torrents in the db
            await update_uncached_status(False, hash, index, config["debridService"], derived_key)

            # Cache the new download link
            await cache_download_link(config["debridApiKey"], hash, index, download_link)

        if (
            settings.PROXY_DEBRID_STREAM
            and settings.PROXY_DEBRID_STREAM_PASSWORD
            == config["debridStreamProxyPassword"]
        ):
            if settings.PROXY_DEBRID_STREAM_MAX_CONNECTIONS != -1:
                active_ip_connections = await database.fetch_all(
                    "SELECT ip, COUNT(*) as connections FROM active_connections GROUP BY ip"
                )
                if any(
                    connection["ip"] == ip
                    and connection["connections"]
                    >= settings.PROXY_DEBRID_STREAM_MAX_CONNECTIONS
                    for connection in active_ip_connections
                ):
                    return FileResponse("comet/assets/proxylimit.mp4")

            proxy = None

            class Streamer:
                def __init__(self, id: str):
                    self.id = id

                    self.client = httpx.AsyncClient(proxy=proxy, timeout=None)
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

            try:
                if config["debridService"] != "torbox":
                    response = await session.head(
                        download_link, headers={"Range": range_header}
                    )
                else:
                    response = await session.get(
                        download_link, headers={"Range": range_header}
                    )
            except aiohttp.ClientResponseError as e:
                if e.status == 503 and config["debridService"] == "alldebrid":
                    proxy = (
                        settings.DEBRID_PROXY_URL
                    )  # proxy is needed only to proxy alldebrid streams

                    response = await session.head(
                        download_link, headers={"Range": range_header}, proxy=proxy
                    )
                else:
                    logger.warning(f"Exception while proxying {download_link}: {e}")
                    return

            if response.status == 206 or (
                response.status == 200 and config["debridService"] == "torbox"
            ):
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

            return FileResponse("comet/assets/uncached.mp4")

        return RedirectResponse(download_link, status_code=302)
