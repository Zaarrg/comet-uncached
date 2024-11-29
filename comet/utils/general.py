import base64
import hashlib
import json
import os
import re
import time
import zlib
from typing import Literal, List, Union, Callable, Any
from urllib.parse import quote

import PTT
import aiohttp
import bencodepy
import asyncio

from RTN import parse, title_match
from aiohttp import ClientSession
from curl_cffi import requests
from databases import Database
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import Request

from comet.utils.logger import logger
from comet.utils.models import settings, ConfigModel, database

languages_emojis = {
    "multi": "🌎",  # Dubbed
    "en": "🇬🇧",  # English
    "ja": "🇯🇵",  # Japanese
    "zh": "🇨🇳",  # Chinese
    "ru": "🇷🇺",  # Russian
    "ar": "🇸🇦",  # Arabic
    "pt": "🇵🇹",  # Portuguese
    "es": "🇪🇸",  # Spanish
    "fr": "🇫🇷",  # French
    "de": "🇩🇪",  # German
    "it": "🇮🇹",  # Italian
    "ko": "🇰🇷",  # Korean
    "hi": "🇮🇳",  # Hindi
    "bn": "🇧🇩",  # Bengali
    "pa": "🇵🇰",  # Punjabi
    "mr": "🇮🇳",  # Marathi
    "gu": "🇮🇳",  # Gujarati
    "ta": "🇮🇳",  # Tamil
    "te": "🇮🇳",  # Telugu
    "kn": "🇮🇳",  # Kannada
    "ml": "🇮🇳",  # Malayalam
    "th": "🇹🇭",  # Thai
    "vi": "🇻🇳",  # Vietnamese
    "id": "🇮🇩",  # Indonesian
    "tr": "🇹🇷",  # Turkish
    "he": "🇮🇱",  # Hebrew
    "fa": "🇮🇷",  # Persian
    "uk": "🇺🇦",  # Ukrainian
    "el": "🇬🇷",  # Greek
    "lt": "🇱🇹",  # Lithuanian
    "lv": "🇱🇻",  # Latvian
    "et": "🇪🇪",  # Estonian
    "pl": "🇵🇱",  # Polish
    "cs": "🇨🇿",  # Czech
    "sk": "🇸🇰",  # Slovak
    "hu": "🇭🇺",  # Hungarian
    "ro": "🇷🇴",  # Romanian
    "bg": "🇧🇬",  # Bulgarian
    "sr": "🇷🇸",  # Serbian
    "hr": "🇭🇷",  # Croatian
    "sl": "🇸🇮",  # Slovenian
    "nl": "🇳🇱",  # Dutch
    "da": "🇩🇰",  # Danish
    "fi": "🇫🇮",  # Finnish
    "sv": "🇸🇪",  # Swedish
    "no": "🇳🇴",  # Norwegian
    "ms": "🇲🇾",  # Malay
    "la": "💃🏻",  # Latino
}


def get_language_emoji(language: str):
    language_formatted = language.lower()
    return (
        languages_emojis[language_formatted]
        if language_formatted in languages_emojis
        else language
    )


translation_table = {
    "ā": "a",
    "ă": "a",
    "ą": "a",
    "ć": "c",
    "č": "c",
    "ç": "c",
    "ĉ": "c",
    "ċ": "c",
    "ď": "d",
    "đ": "d",
    "è": "e",
    "é": "e",
    "ê": "e",
    "ë": "e",
    "ē": "e",
    "ĕ": "e",
    "ę": "e",
    "ě": "e",
    "ĝ": "g",
    "ğ": "g",
    "ġ": "g",
    "ģ": "g",
    "ĥ": "h",
    "î": "i",
    "ï": "i",
    "ì": "i",
    "í": "i",
    "ī": "i",
    "ĩ": "i",
    "ĭ": "i",
    "ı": "i",
    "ĵ": "j",
    "ķ": "k",
    "ĺ": "l",
    "ļ": "l",
    "ł": "l",
    "ń": "n",
    "ň": "n",
    "ñ": "n",
    "ņ": "n",
    "ŉ": "n",
    "ó": "o",
    "ô": "o",
    "õ": "o",
    "ö": "o",
    "ø": "o",
    "ō": "o",
    "ő": "o",
    "œ": "oe",
    "ŕ": "r",
    "ř": "r",
    "ŗ": "r",
    "š": "s",
    "ş": "s",
    "ś": "s",
    "ș": "s",
    "ß": "ss",
    "ť": "t",
    "ţ": "t",
    "ū": "u",
    "ŭ": "u",
    "ũ": "u",
    "û": "u",
    "ü": "u",
    "ù": "u",
    "ú": "u",
    "ų": "u",
    "ű": "u",
    "ŵ": "w",
    "ý": "y",
    "ÿ": "y",
    "ŷ": "y",
    "ž": "z",
    "ż": "z",
    "ź": "z",
    "æ": "ae",
    "ǎ": "a",
    "ǧ": "g",
    "ə": "e",
    "ƒ": "f",
    "ǐ": "i",
    "ǒ": "o",
    "ǔ": "u",
    "ǚ": "u",
    "ǜ": "u",
    "ǹ": "n",
    "ǻ": "a",
    "ǽ": "ae",
    "ǿ": "o",
}

translation_table = str.maketrans(translation_table)
info_hash_pattern = re.compile(r"\b([a-fA-F0-9]{40})\b")


def translate(title: str):
    return title.translate(translation_table)


VIDEO_FILE_EXTENSIONS = [
    ".mkv", ".mp4", ".avi", ".mov", ".flv", ".wmv", ".webm", ".mpg", ".mpeg",
    ".m4v", ".3gp", ".3g2", ".ogv", ".ogg", ".drc", ".gif", ".gifv", ".mng",
    ".qt", ".yuv", ".rm", ".rmvb", ".asf", ".amv", ".m4p", ".mpe", ".mpv",
    ".m2v", ".svi", ".mxf", ".roq", ".nsv", ".f4v", ".f4p", ".f4a", ".f4b"
]


def is_video(title: str):
    return title.endswith(
        tuple(
            VIDEO_FILE_EXTENSIONS
        )
    )


def remove_file_extension(title):
    regex_pattern = r'\.(' + '|'.join(ext.lstrip('.') for ext in VIDEO_FILE_EXTENSIONS) + ')$'
    return re.sub(regex_pattern, '', title, flags=re.IGNORECASE)


def bytes_to_size(bytes: int):
    sizes = ["Bytes", "KB", "MB", "GB", "TB"]
    if bytes == 0:
        return "0 Byte"

    i = 0
    while bytes >= 1024 and i < len(sizes) - 1:
        bytes /= 1024
        i += 1

    return f"{round(bytes, 2)} {sizes[i]}"


def derive_key(token: str, salt: bytes = b'comet_fast') -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(token.encode())


def short_encrypt(data: str, token: str) -> str:
    compressed = zlib.compress(data.encode('utf-8'), level=9)
    key = derive_key(token)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encrypted = cipher.encryptor().update(compressed)
    return base64.urlsafe_b64encode(nonce + encrypted).decode('ascii').rstrip('=')


def short_decrypt(encoded_data: str, token: str) -> str:
    full_payload = base64.urlsafe_b64decode(encoded_data + '=' * (-len(encoded_data) % 4))
    nonce, encrypted = full_payload[:16], full_payload[16:]
    key = derive_key(token)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decrypted = cipher.decryptor().update(encrypted)
    return zlib.decompress(decrypted).decode('utf-8')


def is_encrypted(s: str) -> bool:
    try:
        json.loads(base64.b64decode(s + '=' * (-len(s) % 4)).decode())
        return False
    except:
        return True


def get_language_codes(languages):
    def find_language_code(lang):
        for code, name in PTT.parse.LANGUAGES_TRANSLATION_TABLE.items():
            if name.lower() == lang.lower():
                return code
        return None

    return [find_language_code(lang) for lang in languages]


def language_to_country_code(lang_codes):
    lang_to_country = {
        "en": "US", "ja": "JP", "zh": "CN", "ru": "RU", "ar": "SA", "pt": "PT",
        "es": "ES", "fr": "FR", "de": "DE", "it": "IT", "ko": "KR", "hi": "IN",
        "bn": "BD", "pa": "IN", "mr": "IN", "gu": "IN", "ta": "IN", "te": "IN",
        "kn": "IN", "ml": "IN", "th": "TH", "vi": "VN", "id": "ID", "tr": "TR",
        "he": "IL", "fa": "IR", "uk": "UA", "el": "GR", "lt": "LT", "lv": "LV",
        "et": "EE", "pl": "PL", "cs": "CZ", "sk": "SK", "hu": "HU", "ro": "RO",
        "bg": "BG", "sr": "RS", "hr": "HR", "sl": "SI", "nl": "NL", "da": "DK",
        "fi": "FI", "sv": "SE", "no": "NO", "ms": "MY"
    }

    return [lang_to_country.get(code, code.upper()) for code in lang_codes]


def config_check(config_data: str):
    try:
        config = None
        if settings.TOKEN and is_encrypted(config_data):
            config = json.loads(short_decrypt(config_data, settings.TOKEN))
        else:
            config = json.loads(base64.b64decode(config_data + '=' * (-len(config_data) % 4)).decode())

        validated_config = ConfigModel(**config)
        return validated_config.model_dump()
    except Exception as e:
        logger.error(f"Error checking config: {e}")
        return False


def get_debrid_extension(debridService: str):
    debrid_extension = None
    if debridService == "realdebrid":
        debrid_extension = "RD"
    elif debridService == "alldebrid":
        debrid_extension = "AD"
    elif debridService == "premiumize":
        debrid_extension = "PM"
    elif debridService == "torbox":
        debrid_extension = "TB"
    elif debridService == "debridlink":
        debrid_extension = "DL"

    return debrid_extension


async def get_indexer_manager(
        session: aiohttp.ClientSession,
        indexer_manager_type: str,
        indexers: list,
        query: str,
):
    results = []
    try:
        indexers = [indexer.replace("_", " ") for indexer in indexers]

        if indexer_manager_type == "jackett":

            async def fetch_jackett_results(
                    session: aiohttp.ClientSession, indexer: str, query: str
            ):
                try:
                    async with session.get(
                            f"{settings.INDEXER_MANAGER_URL}/api/v2.0/indexers/all/results?apikey={settings.INDEXER_MANAGER_API_KEY}&Query={query}&Tracker[]={indexer}",
                            timeout=aiohttp.ClientTimeout(
                                total=settings.INDEXER_MANAGER_TIMEOUT
                            ),
                    ) as response:
                        response_json = await response.json()
                        return response_json.get("Results", [])
                except Exception as e:
                    logger.warning(
                        f"Exception while fetching Jackett results for indexer {indexer}: {e}"
                    )
                    return []

            tasks = [
                fetch_jackett_results(session, indexer, query) for indexer in indexers
            ]
            all_results = await asyncio.gather(*tasks)

            for result_set in all_results:
                results.extend(result_set)

        elif indexer_manager_type == "prowlarr":
            get_indexers = await session.get(
                f"{settings.INDEXER_MANAGER_URL}/api/v1/indexer",
                headers={"X-Api-Key": settings.INDEXER_MANAGER_API_KEY},
            )
            get_indexers = await get_indexers.json()

            indexers_id = []
            for indexer in get_indexers:
                if (
                        indexer["name"].lower() in indexers
                        or indexer["definitionName"].lower() in indexers
                ):
                    indexers_id.append(indexer["id"])

            response = await session.get(
                f"{settings.INDEXER_MANAGER_URL}/api/v1/search?query={query}&indexerIds={'&indexerIds='.join(str(indexer_id) for indexer_id in indexers_id)}&type=search",
                headers={"X-Api-Key": settings.INDEXER_MANAGER_API_KEY},
            )
            response = await response.json()

            for result in response:
                result["InfoHash"] = (
                    result["infoHash"] if "infoHash" in result else None
                )
                result["Title"] = result["title"]
                result["Size"] = result["size"]
                result["Link"] = (
                    result["downloadUrl"] if "downloadUrl" in result else None
                )
                result["Tracker"] = result["indexer"]

                results.append(result)
    except Exception as e:
        logger.warning(
            f"Exception while getting {indexer_manager_type} results for {query} with {indexers}: {e}"
        )
        pass

    return results


async def get_zilean(
        session: aiohttp.ClientSession, name: str, log_name: str, season: int, episode: int
):
    results = []
    try:
        show = f"&season={season}&episode={episode}"
        get_dmm = await session.get(
            f"{settings.ZILEAN_URL}/dmm/filtered?query={name}{show if season else ''}"
        )
        get_dmm = await get_dmm.json()

        if isinstance(get_dmm, list):
            take_first = get_dmm[: settings.ZILEAN_TAKE_FIRST]
            for result in take_first:
                object = {
                    "Title": result["raw_title"],
                    "InfoHash": result["info_hash"],
                    "Size": result["size"],
                    "Tracker": "DMM",
                }

                results.append(object)

        logger.info(f"{len(results)} torrents found for {log_name} using title {name} with Zilean")
    except Exception as e:
        logger.warning(
            f"Exception while getting torrents for {log_name} using title {name} with Zilean: {e}"
        )
        pass

    return results


async def get_torrentio(log_name: str, type: str, full_id: str):
    results = []
    try:
        try:
            get_torrentio = requests.get(
                f"https://torrentio.strem.fun/stream/{type}/{full_id}.json"
            ).json()
        except:
            get_torrentio = requests.get(
                f"https://torrentio.strem.fun/stream/{type}/{full_id}.json",
                proxies={
                    "http": settings.DEBRID_PROXY_URL,
                    "https": settings.DEBRID_PROXY_URL,
                },
            ).json()

        for torrent in get_torrentio["streams"]:
            title = torrent["title"]
            title_full = title.split("\n👤")[0]
            tracker = title.split("⚙️ ")[1].split("\n")[0]
            seeders = int(title.split("👤")[1].split()[0])

            results.append(
                {
                    "Title": title_full,
                    "InfoHash": torrent["infoHash"],
                    "Size": None,
                    "Tracker": f"Torrentio|{tracker}",
                    "Seeders": seeders
                }
            )

        logger.info(f"{len(results)} torrents found for {log_name} with Torrentio")
    except Exception as e:
        logger.warning(
            f"Exception while getting torrents for {log_name} with Torrentio, your IP is most likely blacklisted (you should try proxying Comet): {e}"
        )
        pass

    return results


import re


def check_completion(raw_title: str, season: str | int) -> bool:
    """
    Determines if a torrent title represents a complete season.

    Checks for:
    1. Season ranges (e.g., S01-S03)
    2. Explicit mentions of complete seasons
    3. Season mentions without episode numbers
    4. Absence of individual episode indicators
    5. Batch releases

    Returns True if likely a complete season, False otherwise.
    """
    if not season:
        return False
    season_int = int(season)

    # Normalize the title for processing
    raw_title_lower = raw_title.lower()

    # Check for explicit mentions of batch or complete/full season
    if any(keyword in raw_title_lower for keyword in ['(batch)', 'batch', 'complete', 'full']):
        return True

    # Split the title into parts for further processing
    title_parts = re.split(r'[/\\|]|\n', raw_title_lower)

    for part in title_parts:
        # Handle ranges like S01-S03
        if re.search(rf's0?(\d+)-s0?(\d+)', part):
            start, end = map(int, re.search(rf's0?(\d+)-s0?(\d+)', part).groups())
            if start <= season_int <= end:
                return True

        # Check for "complete season" patterns
        complete_patterns = [
            rf'(?:season\s*{season_int}|s0?{season_int})\s*(?:\[|\(|$)',
            rf's0?{season_int}\s*(?:complete|full)',
            rf'(?:complete|full)\s*(?:season\s*{season_int}|s0?{season_int})'
        ]
        if any(re.search(p, part) for p in complete_patterns):
            return True

        # Look for season mentions without episode indicators
        if re.search(rf'(?:season\s*{season_int}|s0?{season_int})', part) and not re.search(r'(?:e\d+|episode\s*\d+)',
                                                                                            part):
            return True

    # If no match, check for individual episode indicators to rule out complete season
    episode_indicators = [r's\d+e\d+', r'- \d+', r'episode \d+', r'e\d+']
    return not any(re.search(p, part) for part in title_parts for p in episode_indicators)


async def filter(torrents: list, title_list: list, year: int):
    results = []
    for torrent in torrents:
        index = torrent[0]
        title = torrent[1]

        if "\n" in title:  # Torrentio title parsing
            title = title.split("\n")[1]
        # Removes alternative titles that would come after a -, / or |
        separators = r'[\/\-|]'
        parts = re.split(separators, title)
        if len(parts) > 1:
            title = parts[0].strip()
        if not title:
            continue

        parsed = parse(title)
        for name in title_list:
            if parsed.parsed_title and not title_match(name, translate(parsed.parsed_title)):
                continue

            if year and parsed.year and year != parsed.year:
                results.append((index, False))
                continue

            results.append((index, True))
            break
        else:
            results.append((index, False))

    return results


async def uncached_select_index(
        files: List[dict],
        search_title: str,
        index: Union[int, str],
        debrid_service: Literal["real_debrid", "debrid_link"]
) -> Union[int, str]:
    """
    Select the appropriate file index or ID from a list of files based on matching titles.

    :param files: List of files from the magnet info.
    :param search_title: Title to search for in the file names.
    :param index: Default fallback index if no match is found.
    :param debrid_service: The debrid service being used ("rd" or "dl").
    :return: The selected file ID or index depending on the service.
    """

    # Service-specific configurations
    service_config = {
        "real_debrid": {
            "file_name_extractor": lambda file: file.get("path", "").split("/")[-1],
            "filter": lambda files: [file for file in files if file.get('selected') != 0],
            "id_getter": lambda file, i: file.get("id"),
            "fallback": lambda idx: int(idx) + 1,
        },
        "debrid_link": {
            "file_name_extractor": lambda file: file.get("name", ""),
            "filter": lambda files: files,  # No filtering for DL
            "id_getter": lambda file, i: i,
            "fallback": lambda idx: int(idx),
        },
    }

    # Ensure service is supported
    if debrid_service not in service_config:
        raise Exception(f"Unsupported debrid service: {debrid_service}")
    # Ensure files list has files
    if len(files) <= 0:
        raise Exception(f"Exception while checking files, no files found, torrent might be stale, for {debrid_service} | {search_title}")

    # Get the config for the selected service
    config = service_config[debrid_service]
    file_name_extractor: Callable[[dict], str] = config["file_name_extractor"]
    file_filter: Callable[[List[dict]], List[dict]] = config["filter"]
    id_getter: Callable[[dict, int], Any] = config["id_getter"]
    fallback: Callable[[int], Any] = config["fallback"]
    selected_id_or_index = None

    # Apply the service-specific filter
    files = file_filter(files)

    # First pass: Match based on exact file names
    for i, file in enumerate(files):
        file_name = file_name_extractor(file)
        if file_name in search_title or remove_file_extension(file_name) == search_title:
            selected_id_or_index = id_getter(file, i)
            break

    # Second pass: Match based on parsed episodes/movies
    if selected_id_or_index is None:
        for i, file in enumerate(files):
            file_name = file_name_extractor(file)
            file_name_parsed = parse(file_name)
            title_parsed = parse(search_title)

            if len(file_name_parsed.episodes) > 0 and file_name_parsed.episodes[0] in title_parsed.episodes:
                selected_id_or_index = id_getter(file, i)
                break
            # Check in case movie. Uncached movies have always index 0 as placeholder. Shows index > 0 (index = episode)
            if (
                    int(index) == 0 and
                    file_name_parsed.normalized_title == title_parsed.normalized_title and
                    file_name_parsed.year == title_parsed.year and
                    file_name_parsed.resolution == title_parsed.resolution
            ):
                selected_id_or_index = id_getter(file, i)
                break

    # Fallback: Use service-specific fallback logic
    if selected_id_or_index is None:
        selected_id_or_index = fallback(index)
        logger.warning(
            f"Exception while selecting files, could not identify correct video file, using fallback, for {debrid_service} | {search_title}"
        )
    return selected_id_or_index


async def uncached_db_find_container_id(debrid_key: str, hash: str) -> str:
    """
    Returns first found containerId for the given hash.
    If returned string not empty caching to debrid has been started.
    If containerId not empty no need for additional download start of this hash.
    """
    query = """
    SELECT containerId
    FROM uncached_torrents
    WHERE debrid_key = :debrid_key AND hash = :hash AND containerId != ''
    """
    result = await database.fetch_one(query, {"hash": hash, "debrid_key": debrid_key})
    if result:
        return result["containerId"]
    else:
        return ""


async def update_torrent_id_uncached_db(debrid_key: str, hash: str, file_index: str, torrent_id: str):
    """
    Sets the Torrent Id for one specific file / uncached torrent
    """
    query = """
    UPDATE uncached_torrents 
    SET torrentId = :torrent_id
    WHERE debrid_key = :debrid_key AND hash = :hash AND file_index = :file_index
    """
    await database.execute(query, {
        "torrent_id": torrent_id,
        "debrid_key": debrid_key,
        "hash": hash,
        "file_index": file_index
    })


async def update_container_id_uncached_db(debrid_key: str, hash: str, container_id: str):
    """
    Sets the Container Id for all uncached torrents with the same hash and debrid key
    """
    query = """
    UPDATE uncached_torrents 
    SET containerId = :container_id
    WHERE debrid_key = :debrid_key AND hash = :hash
    """
    await database.execute(query, {
        "container_id": container_id,
        "debrid_key": debrid_key,
        "hash": hash
    })


async def check_uncached(hash: str, file_index: str, debrid_key: str):
    # Fetch uncached torrent data from the database
    uncached_torrent = await database.fetch_one(
        """
        SELECT torrentId, containerId, title, link, magnet
        FROM uncached_torrents
        WHERE debrid_key = :debrid_key AND hash = :hash AND file_index = :file_index
        """,
        {"debrid_key": debrid_key, "hash": hash, "file_index": file_index}
    )

    if uncached_torrent:
        # Check if the magnet key exists and is not empty/None
        has_magnet = bool(uncached_torrent["magnet"])

        return {
            "torrent_id": uncached_torrent["torrentId"],
            "container_id": uncached_torrent["containerId"],
            "title": uncached_torrent["title"],
            "torrent_link": uncached_torrent["link"],
            "has_magnet": has_magnet
        }
    else:
        return None


async def cache_wipe():
    logger.warning(f"Cache cleanup started.")
    expiration_timestamp = int(time.time()) - settings.CACHE_WIPE_TTL

    # Delete expired entries from the cache table
    result_cache = await database.execute(
        """
        DELETE FROM cache
        WHERE timestamp < :expiration_timestamp
        """,
        {"expiration_timestamp": expiration_timestamp}
    )

    # Delete entries from uncached_torrents where both IDs are empty or expired
    result_uncached = await database.execute(
        """
        DELETE FROM uncached_torrents
        WHERE
            (
                (torrentId IS NULL OR TRIM(torrentId) = '') AND
                (containerId IS NULL OR TRIM(containerId) = '')
            )
            OR
            (timestamp < :expiration_timestamp)
        """,
        {"expiration_timestamp": expiration_timestamp}
    )
    total_deleted = result_cache + result_uncached
    logger.warning(f"Cache cleanup completed. Total entries deleted: {total_deleted}")


async def add_uncached_files(
        files: dict,
        torrents: list,
        cache_key: str,
        log_name: str,
        allowed_tracker_ids: list,
        database: Database,
        season: int,
        episode: int,
        kitsu: bool,
        config: dict,
):
    allowed_tracker_ids_set = {tracker_id.lower() for tracker_id in allowed_tracker_ids}
    found_uncached = 0
    uncached_torrents = []
    current_timestamp = int(time.time())

    for torrent in torrents:
        tracker = torrent.get("Tracker", "")
        tracker_id = torrent.get("TrackerId", "")

        tracker_parts = tracker.split('|')
        if len(tracker_parts) > 1:
            tracker = tracker_parts[0]

        if tracker.lower() in allowed_tracker_ids_set or tracker_id.lower() in allowed_tracker_ids_set:
            info_hash = torrent["InfoHash"]
            if info_hash not in files:
                filename_parsed = {}
                if episode:
                    filename_parsed = parse(torrent["Title"])
                    if kitsu:
                        if episode not in filename_parsed.episodes or filename_parsed.seasons:
                            continue
                    elif (filename_parsed.episodes and episode not in filename_parsed.episodes) or (
                            filename_parsed.seasons and season not in filename_parsed.seasons):
                        continue
                found_uncached += 1
                # Index key Very important, has to be a unique identifier hash|index for tv shows
                # For movies can be left at 0 as for movies the hash itself is unique enough for every torrent container
                # For Tv Shows uses the episode as index to make it unique.
                # Later on in debrid handle_uncached the real index is determiend based on title and file_name to return the correct download link
                # The index used in the url only is a placeholder to make it unique to make sure the download link / uncached torrents cache can work
                # Real index can only be determined later when the debrid files are known for that uncached torrent
                file_index = episode - 1 if episode else 0
                complete = False
                stremio_data = {
                    "index": file_index,
                    "title": torrent["Title"],
                    "size": torrent.get("Size") if torrent.get("Size") is not None else 0,
                    "uncached": True,
                    "complete": None,
                    "seeders": torrent.get("Seeders") if torrent.get("Seeders") is not None else 0
                }
                # Update files for stremio and uncached_torrents for database insertion
                files[info_hash] = stremio_data

                uncached_torrents.append({
                    "debrid_key": config["debridApiKey"],
                    "hash": info_hash,
                    "file_index": file_index,
                    "torrentId": "",
                    "containerId": "",
                    "title": torrent["Title"],
                    "link": torrent.get("Link", ""),
                    "magnet": torrent.get("MagnetUri", ""),
                    "cacheKey": cache_key,
                    "timestamp": current_timestamp
                })

    # Batch insert uncached torrents
    if uncached_torrents:
        insert_sql = f"""
        INSERT {'OR IGNORE ' if settings.DATABASE_TYPE == 'sqlite' else ''}INTO uncached_torrents
        (debrid_key, hash, file_index, torrentId, containerId, title, link, magnet, cacheKey, timestamp)
        VALUES (:debrid_key, :hash, :file_index, :torrentId, :containerId, :title, :link, :magnet, :cacheKey, :timestamp)
        {'' if settings.DATABASE_TYPE == 'sqlite' else 'ON CONFLICT (debrid_key, hash, file_index) DO NOTHING'}
        """
        await database.execute_many(insert_sql, uncached_torrents)

    logger.info(
        f"{found_uncached} uncached files found on {', '.join(allowed_tracker_ids)} for {log_name}"
    )


async def get_torrent_hash(session: aiohttp.ClientSession, torrent: tuple):
    index = torrent[0]
    torrent = torrent[1]
    if "InfoHash" in torrent and torrent["InfoHash"] is not None:
        return (index, torrent["InfoHash"].lower())

    url = torrent["Link"]

    try:
        timeout = aiohttp.ClientTimeout(total=settings.GET_TORRENT_TIMEOUT)
        response = await session.get(url, allow_redirects=False, timeout=timeout)
        if response.status == 200:
            torrent_data = await response.read()
            torrent_dict = bencodepy.decode(torrent_data)
            info = bencodepy.encode(torrent_dict[b"info"])
            hash = hashlib.sha1(info).hexdigest()
        else:
            location = response.headers.get("Location", "")
            if not location:
                return (index, None)

            match = info_hash_pattern.search(location)
            if not match:
                return (index, None)

            hash = match.group(1).upper()

        return (index, hash.lower())
    except Exception as e:
        logger.warning(
            f"Exception while getting torrent info hash for {torrent['indexer'] if 'indexer' in torrent else (torrent['Tracker'] if 'Tracker' in torrent else '')}|{url}: {e}"
        )

        return (index, None)


def get_balanced_hashes(hashes: dict, config: dict, type: str):
    max_results = config["maxResults"]

    max_size = config["maxSize"]
    config_resolutions = [resolution.lower() for resolution in config["resolutions"]]
    config_resolutions_order = config.get("resolutionsOrder", [])
    include_all_resolutions = "all" in config_resolutions
    config_language_preference = {
        language.replace("_", " ").capitalize() for language in config["languagePreference"]
    }

    languages = [language.lower() for language in config["languages"]]
    include_all_languages = "all" in languages
    if not include_all_languages:
        config_languages = [
            code
            for code, name in PTT.parse.LANGUAGES_TRANSLATION_TABLE.items()
            if name.lower() in languages
        ]

    hashes_by_resolution = {}
    for hash, hash_data in hashes.items():
        hash_info = hash_data["data"]

        if max_size != 0 and hash_info["size"] > max_size:
            continue

        if (
                not include_all_languages
                and not any(lang in hash_info["languages"] for lang in config_languages)
                and ("multi" not in languages if hash_info["dubbed"] else True)
        ):
            continue

        resolution = hash_info["resolution"]
        hash_info["resolution"] = hash_info["resolution"].capitalize()

        if not include_all_resolutions and resolution not in config_resolutions:
            continue

        if hash_info['uncached'] and (include_all_resolutions or 'Uncached' in config_resolutions):
            hash_info["resolution"] = 'Uncached'
            resolution = 'Uncached'

        if resolution not in hashes_by_resolution:
            hashes_by_resolution[resolution] = []
        hashes_by_resolution[resolution].append(hash)

    # Sorting
    hashes_by_resolution = apply_sorting(
        hashes_by_resolution,
        hashes,
        config_resolutions_order,
        config_language_preference,
        config.get("sortType", "Sort_by_Resolution_then_Rank"),
        config.get("sortPreference", ""),
        type,
    )

    total_resolutions = len(hashes_by_resolution)
    if max_results == 0 or total_resolutions == 0:
        return hashes_by_resolution

    hashes_per_resolution = max_results // total_resolutions
    extra_hashes = max_results % total_resolutions

    balanced_hashes = {}
    for resolution, hash_list in hashes_by_resolution.items():
        selected_count = hashes_per_resolution + (1 if extra_hashes > 0 else 0)
        balanced_hashes[resolution] = hash_list[:selected_count]
        if extra_hashes > 0:
            extra_hashes -= 1

    selected_total = sum(len(hashes) for hashes in balanced_hashes.values())
    if selected_total < max_results:
        missing_hashes = max_results - selected_total
        for resolution, hash_list in hashes_by_resolution.items():
            if missing_hashes <= 0:
                break
            current_count = len(balanced_hashes[resolution])
            available_hashes = hash_list[current_count: current_count + missing_hashes]
            balanced_hashes[resolution].extend(available_hashes)
            missing_hashes -= len(available_hashes)

    return balanced_hashes


def apply_sorting(hashes_by_resolution, hashes, config_resolutions_order, config_languages_preference, sort_type,
                  sort_preference, type):
    """Apply the specified sorting function based on the sort_type string. Sorts Uncached always by seeders"""
    resolution_index_map = {res: i for i, res in enumerate(config_resolutions_order or [
        "4K", "2160p", "1440p", "1080p", "720p", "576p", "480p", "360p", "Uncached", "Unknown"
    ])}

    languages_set = set(config_languages_preference) if config_languages_preference else None

    def sort_by_resolution(res):
        return resolution_index_map.get(res, len(config_resolutions_order))

    def sort_by_priority_language(hash_key):
        languages = hashes[hash_key]["data"].get("language", [])
        return next((i for i, lang in enumerate(config_languages_preference) if lang in languages),
                    len(config_languages_preference))

    def sort_uncached_by_seeders(sorted_hashes_by_resolution):
        if "Uncached" in sorted_hashes_by_resolution:
            sorted_hashes_by_resolution["Uncached"].sort(
                key=lambda hash_key: -int(hashes[hash_key]["data"].get("seeders", 0))
            )
        return sorted_hashes_by_resolution

    def sort_by_resolution_then_rank():
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        for res, hash_list in sorted_hashes_by_resolution.items():
            hash_list.sort(key=lambda hash_key: (
            -int(hashes[hash_key]["data"].get("rank", 0)), -hashes[hash_key]["data"].get("size", 0)))
        return sort_uncached_by_seeders(sorted_hashes_by_resolution)

    def sort_by_resolution_then_seeders():
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        for res, hash_list in sorted_hashes_by_resolution.items():
            hash_list.sort(key=lambda hash_key: -int(hashes[hash_key]["data"].get("seeders", 0)))
        return sort_uncached_by_seeders(sorted_hashes_by_resolution)

    def sort_by_resolution_then_size():
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        for res, hash_list in sorted_hashes_by_resolution.items():
            hash_list.sort(key=lambda hash_key: -hashes[hash_key]["data"].get("size", 0))
        return sort_uncached_by_seeders(sorted_hashes_by_resolution)

    def prioritize_languages(sorted_hashes_by_resolution):
        """Prioritize torrents by languages according to config_languages_preference."""
        if not languages_set:
            return sorted_hashes_by_resolution

        for res, hash_list in sorted_hashes_by_resolution.items():
            prioritized = [hash_key for hash_key in hash_list if
                           languages_set.intersection(hashes[hash_key]["data"].get("language", []))]
            non_prioritized = [hash_key for hash_key in hash_list if hash_key not in prioritized]
            prioritized.sort(key=sort_by_priority_language)
            sorted_hashes_by_resolution[res] = prioritized + non_prioritized
        return sorted_hashes_by_resolution

    def prioritize_completion(sorted_hashes_by_resolution):
        if type != "series":
            return sorted_hashes_by_resolution

        for res, hash_list in sorted_hashes_by_resolution.items():
            complete = [hash_key for hash_key in hash_list if hashes[hash_key]["data"].get("complete", False)]
            incomplete = [hash_key for hash_key in hash_list if hash_key not in complete]

            # Sort complete seasons based on the original sorting criteria
            if sort_type == "Sort_by_Resolution_then_Rank":
                complete.sort(key=lambda hash_key: (
                -int(hashes[hash_key]["data"].get("rank", 0)), -hashes[hash_key]["data"].get("size", 0)))
            elif sort_type == "Sort_by_Resolution_then_Seeders":
                complete.sort(key=lambda hash_key: -int(hashes[hash_key]["data"].get("seeders", 0)))
            elif sort_type == "Sort_by_Resolution_then_Size":
                complete.sort(key=lambda hash_key: -hashes[hash_key]["data"].get("size", 0))

            sorted_hashes_by_resolution[res] = complete + incomplete
        return sorted_hashes_by_resolution

    # Main sorting logic
    if sort_type == "Sort_by_Resolution_then_Rank":
        sorted_hashes_by_resolution = sort_by_resolution_then_rank()
    elif sort_type == "Sort_by_Resolution_then_Seeders":
        sorted_hashes_by_resolution = sort_by_resolution_then_seeders()
    elif sort_type == "Sort_by_Resolution_then_Size":
        sorted_hashes_by_resolution = sort_by_resolution_then_size()
    else:
        logger.warning(f"Invalid sort type, results will be sorted by resolution then rank")
        sorted_hashes_by_resolution = sort_by_resolution_then_rank()

    # Apply completion prioritization if needed
    if sort_preference == "Completion" and type == "series":
        logger.info(f"Sorting results by complete seasons")
        sorted_hashes_by_resolution = prioritize_completion(sorted_hashes_by_resolution)

    # Apply language prioritization if needed
    if languages_set:
        logger.info(f"Sorting results by language Preference {config_languages_preference}")
        sorted_hashes_by_resolution = prioritize_languages(sorted_hashes_by_resolution)

    return sorted_hashes_by_resolution


def format_metadata(data: dict):
    extras = []
    if data["quality"]:
        extras.append(data["quality"])
    if data["hdr"]:
        extras.extend(data["hdr"])
    if data["codec"]:
        extras.append(data["codec"])
    if data["audio"]:
        extras.extend(data["audio"])
    if data["channels"]:
        extras.extend(data["channels"])
    if data["bit_depth"]:
        extras.append(data["bit_depth"])
    if data["network"]:
        extras.append(data["network"])
    if data["group"]:
        extras.append(data["group"])

    return "|".join(extras)


async def get_localized_titles(language_codes, country_codes, id: str, session: ClientSession):
    headers = {
        "content-type": "application/json"
    }
    params = {
        "operationName": "TitleAkasPaginated",
        "variables": f'{{"const":"{id}","first":8000}}',
        "extensions": '{"persistedQuery":{"sha256Hash":"48d4f7bfa73230fb550147bd4704d8050080e65fe2ad576da6276cac2330e446","version":1}}'
    }
    try:
        gathered_localized_titles = await session.get(f'https://caching.graphql.imdb.com/', params=params,
                                                      headers=headers)
    except Exception as e:
        logger.warning(
            f"Exception while getting localized titles: {e}"
        )
        return []
    localized_titles = await gathered_localized_titles.json()

    return extract_localized_titles(localized_titles, language_codes, country_codes)


def extract_localized_titles(data: dict, language_codes, country_codes):
    results = {}
    edges = data.get('data', {}).get('title', {}).get('akas', {}).get('edges', [])

    for edge in edges:
        node = edge.get('node', {})
        country = node.get('country', {})
        language = node.get('language', {})
        country_id = country.get('id', '') if country else ''
        language_id = language.get('id', '') if language else ''

        if language_id in language_codes or country_id in country_codes:
            display_prop = node.get('displayableProperty', {})
            title = display_prop.get('value', {}).get('plainText', '')
            qualifiers = display_prop.get('qualifiersInMarkdownList') or []

            is_dubbed = any("dubbed" in (qualifier.get('plainText', '').lower()) for qualifier in qualifiers)

            if is_dubbed or country_id not in results:
                results[country_id] = title
    return results


def format_title(data: dict, config: dict):
    title = ""
    if "All" in config["resultFormat"] or "Title" in config["resultFormat"]:
        title += f"{data['title']}\n"

    if "All" in config["resultFormat"] or "Metadata" in config["resultFormat"]:
        metadata = format_metadata(data)
        if metadata != "":
            title += f"💿 {metadata}\n"

    if "All" in config["resultFormat"] or "Uncached" in config["resultFormat"]:
        if data.get("uncached", False):
            title += f"⚠️ Uncached"

    if "All" in config["resultFormat"] or "Size" in config["resultFormat"]:
        title += f"💾 {bytes_to_size(data['size'])} "

    if "All" in config["resultFormat"] or "Seeders" in config["resultFormat"] or data.get("uncached", True):
        if data.get('seeders', None) is not None:
            title += f"🌱 {data.get('seeders')}"

    if "All" in config["resultFormat"] or "Tracker" in config["resultFormat"]:
        title += f"🔎 {data['tracker'] if 'tracker' in data else '?'}"

    if "All" in config["resultFormat"] or "Complete" in config["resultFormat"]:
        if data.get("complete", False):
            title += f"📦 Complete Season"

    if "All" in config["resultFormat"] or "Languages" in config["resultFormat"]:
        languages = data["languages"]
        if data["dubbed"]:
            languages.insert(0, "multi")
        formatted_languages = (
            "/".join(get_language_emoji(language) for language in languages)
            if languages
            else None
        )
        languages_str = "\n" + formatted_languages if formatted_languages else ""
        title += f"{languages_str}"

    if title == "":
        # Without this, Streamio shows SD as the result, which is confusing
        title = "Empty result format configuration"

    return title


def get_client_ip(request: Request):
    return (
        request.headers["cf-connecting-ip"]
        if "cf-connecting-ip" in request.headers
        else request.client.host
    )
