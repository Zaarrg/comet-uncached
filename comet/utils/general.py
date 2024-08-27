import base64
import hashlib
import json
import os
import re
import time
import zlib

import aiohttp
import bencodepy

from RTN import parse, title_match, Torrent
from aiohttp import ClientSession
from curl_cffi import requests
from databases import Database
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from comet.utils.logger import logger
from comet.utils.models import settings, ConfigModel, database

languages_emojis = {
    "multi_subs": "🌐",
    "multi_audio": "🌎",
    "dual_audio": "🔉",
    "english": "🇬🇧",
    "japanese": "🇯🇵",
    "korean": "🇰🇷",
    "taiwanese": "🇹🇼",
    "chinese": "🇨🇳",
    "french": "🇫🇷",
    "latino": "💃🏻",
    "spanish": "🇪🇸",
    "portuguese": "🇵🇹",
    "italian": "🇮🇹",
    "greek": "🇬🇷",
    "german": "🇩🇪",
    "russian": "🇷🇺",
    "ukrainian": "🇺🇦",
    "hindi": "🇮🇳",
    "telugu": "🇮🇳",
    "tamil": "🇮🇳",
    "lithuanian": "🇱🇹",
    "latvian": "🇱🇻",
    "estonian": "🇪🇪",
    "polish": "🇵🇱",
    "czech": "🇨🇿",
    "slovakian": "🇸🇰",
    "hungarian": "🇭🇺",
    "romanian": "🇷🇴",
    "bulgarian": "🇧🇬",
    "serbian": "🇷🇸",
    "croatian": "🇭🇷",
    "slovenian": "🇸🇮",
    "dutch": "🇳🇱",
    "danish": "🇩🇰",
    "finnish": "🇫🇮",
    "swedish": "🇸🇪",
    "norwegian": "🇳🇴",
    "arabic": "🇸🇦",
    "turkish": "🇹🇷",
    "vietnamese": "🇻🇳",
    "indonesian": "🇮🇩",
    "thai": "🇹🇭",
    "malay": "🇲🇾",
    "hebrew": "🇮🇱",
    "persian": "🇮🇷",
    "bengali": "🇧🇩",
}


def get_language_emoji(language: str):
    language_formatted = language.replace(" ", "_").lower()
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


def is_video(title: str):
    return title.endswith(
        tuple(
            [
                ".mkv",
                ".mp4",
                ".avi",
                ".mov",
                ".flv",
                ".wmv",
                ".webm",
                ".mpg",
                ".mpeg",
                ".m4v",
                ".3gp",
                ".3g2",
                ".ogv",
                ".ogg",
                ".drc",
                ".gif",
                ".gifv",
                ".mng",
                ".avi",
                ".mov",
                ".qt",
                ".wmv",
                ".yuv",
                ".rm",
                ".rmvb",
                ".asf",
                ".amv",
                ".m4p",
                ".m4v",
                ".mpg",
                ".mp2",
                ".mpeg",
                ".mpe",
                ".mpv",
                ".mpg",
                ".mpeg",
                ".m2v",
                ".m4v",
                ".svi",
                ".3gp",
                ".3g2",
                ".mxf",
                ".roq",
                ".nsv",
                ".flv",
                ".f4v",
                ".f4p",
                ".f4a",
                ".f4b",
            ]
        )
    )


lang_map = {
    'eng': 'en', 'en': 'en', 'english': 'en',
    'spa': 'es', 'es': 'es', 'spanish': 'es',
    'fre': 'fr', 'fra': 'fr', 'fr': 'fr', 'french': 'fr',
    'ger': 'de', 'deu': 'de', 'de': 'de', 'german': 'de',
    'ita': 'it', 'it': 'it', 'italian': 'it',
    'por': 'pt', 'pt': 'pt', 'portuguese': 'pt',
    'rus': 'ru', 'ru': 'ru', 'russian': 'ru',
    'jpn': 'ja', 'jap': 'ja', 'ja': 'ja', 'japanese': 'ja',
    'chi': 'zh', 'zho': 'zh', 'zh': 'zh', 'chinese': 'zh',
    'kor': 'ko', 'ko': 'ko', 'korean': 'ko',
    'hin': 'hi', 'hi': 'hi', 'hindi': 'hi',
    'tur': 'tr', 'tr': 'tr', 'turkish': 'tr',
    'ara': 'ar', 'ar': 'ar', 'arabic': 'ar',
    'pol': 'pl', 'pl': 'pl', 'polish': 'pl',
    'dut': 'nl', 'nld': 'nl', 'nl': 'nl', 'dutch': 'nl',
    'swe': 'sv', 'sv': 'sv', 'swedish': 'sv',
    'dan': 'da', 'da': 'da', 'danish': 'da',
    'nor': 'nb', 'norwegian': 'nb',
    'fin': 'fi', 'fi': 'fi', 'finnish': 'fi',
    'gre': 'el', 'ell': 'el', 'el': 'el', 'greek': 'el',
    'hun': 'hu', 'hu': 'hu', 'hungarian': 'hu',
    'cze': 'cs', 'ces': 'cs', 'cs': 'cs', 'czech': 'cs',
    'rom': 'ro', 'ron': 'ro', 'ro': 'ro', 'romanian': 'ro',
    'tha': 'th', 'th': 'th', 'thai': 'th',
    'vie': 'vi', 'vi': 'vi', 'vietnamese': 'vi',
    'ind': 'id', 'id': 'id', 'indonesian': 'id',
    'heb': 'he', 'he': 'he', 'hebrew': 'he',
    'ukr': 'uk', 'uk': 'uk', 'ukrainian': 'uk',
    'per': 'fa', 'fas': 'fa', 'fa': 'fa', 'persian': 'fa',
    'srp': 'sr', 'sr': 'sr', 'serbian': 'sr',
    'hrv': 'hr', 'hr': 'hr', 'croatian': 'hr',
    'bul': 'bg', 'bg': 'bg', 'bulgarian': 'bg',
    'slk': 'sk', 'sk': 'sk', 'slovak': 'sk',
    'slv': 'sl', 'sl': 'sl', 'slovenian': 'sl',
    'lit': 'lt', 'lt': 'lt', 'lithuanian': 'lt',
    'lav': 'lv', 'lv': 'lv', 'latvian': 'lv',
    'est': 'et', 'et': 'et', 'estonian': 'et',
    'tam': 'ta', 'ta': 'ta', 'tamil': 'ta',
    'tel': 'te', 'te': 'te', 'telugu': 'te',
    'urd': 'ur', 'ur': 'ur', 'urdu': 'ur',
    'ben': 'bn', 'bn': 'bn', 'bengali': 'bn',
    'may': 'ms', 'msa': 'ms', 'ms': 'ms', 'malay': 'ms',
    'fil': 'tl', 'tl': 'tl', 'filipino': 'tl', 'tagalog': 'tl'
}

code_to_full_name = {v: k for k, v in lang_map.items() if len(k) > 3}
pattern = re.compile(r'\b(?:[A-Za-z]{2,3}|[A-Za-z]{3,})(?:[.,+&/-](?:[A-Za-z]{2,3}|[A-Za-z]{3,}))*\b', re.IGNORECASE)


def enhance_languages(torrent: Torrent):
    raw_title = torrent['raw_title']
    data = torrent['data']
    existing_lang_codes = data.get('lang_codes', {})

    new_lang_codes: set[str] = set()
    for match in pattern.finditer(raw_title):
        for lang in re.split(r'[.,+&/-]+', match.group(0)):
            lang_code = lang_map.get(lang.lower())
            if lang_code:
                new_lang_codes.add(lang_code)

    all_lang_codes = set(existing_lang_codes.values()).union(new_lang_codes)

    updated_lang_codes = {}
    full_names = []
    for code in all_lang_codes:
        full_name = code_to_full_name.get(code, '').capitalize()
        if full_name:
            updated_lang_codes[full_name] = code
            full_names.append(full_name)

    data['language'] = sorted(full_names)
    data['lang_codes'] = updated_lang_codes

    return torrent


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


def config_check(config_data: str):
    try:
        if settings.TOKEN and is_encrypted(config_data):
            config_data = short_decrypt(config_data, settings.TOKEN)

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
        timeout = aiohttp.ClientTimeout(total=settings.INDEXER_MANAGER_TIMEOUT)

        if indexer_manager_type == "jackett":
            response = await session.get(
                f"{settings.INDEXER_MANAGER_URL}/api/v2.0/indexers/all/results?apikey={settings.INDEXER_MANAGER_API_KEY}&Query={query}&Tracker[]={'&Tracker[]='.join(indexer for indexer in indexers)}",
                timeout=timeout,
            )
            response = await response.json()

            for result in response["Results"]:
                results.append(result)

        if indexer_manager_type == "prowlarr":
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
        if not season:
            get_dmm = await session.post(
                f"{settings.ZILEAN_URL}/dmm/search", json={"queryText": name}
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
        else:
            get_dmm = await session.get(
                f"{settings.ZILEAN_URL}/dmm/filtered?query={name}&season={season}&episode={episode}"
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


async def filter(torrents: list, title_list: list):
    results = []
    for torrent in torrents:
        index = torrent[0]
        title = torrent[1]

        if "\n" in title:  # Torrentio title parsing
            title = title.split("\n")[1]
        # Removes alternative titles that would come after a -, / or |
        separators = r'[\/\-|]'
        parts = re.split(separators, title)
        title = parts[0].strip()

        for name in title_list:
            if title_match(name, translate(parse(title).parsed_title)):
                results.append((index, True))
                break
        else:
            results.append((index, False))

    return results


async def check_uncached(hash: str):
    # Fetch uncached torrent data from the database
    uncached_torrent = await database.fetch_one(
        "SELECT data, torrentId FROM uncached_torrents WHERE hash = :hash",
        {"hash": hash}
    )

    if uncached_torrent:
        # Extract relevant information from the uncached torrent data
        torrent_data = json.loads(uncached_torrent["data"])
        torrent_id = uncached_torrent["torrentId"]
        torrent_link = torrent_data.get("link")
        index = torrent_data.get("index")

        # Check if the magnet key exists and is not empty/None
        has_magnet = bool(torrent_data.get("magnet"))

        return {
            "torrent_id": torrent_id,
            "torrent_link": torrent_link,
            "index": index,
            "has_magnet": has_magnet
        }
    else:
        return None


async def add_uncached_files(
        files: dict,
        torrents: list,
        cache_key: str,
        log_name: str,
        allowed_tracker_ids: list,
        database: Database
):
    tracker_key = "Tracker" if settings.INDEXER_MANAGER_TYPE == 'prowlarr' else "TrackerId"
    allowed_tracker_ids_set = {tracker_id.lower() for tracker_id in allowed_tracker_ids}
    found_uncached = 0
    uncached_torrents = []
    current_timestamp = int(time.time())

    for torrent in torrents:
        tracker = torrent.get(tracker_key, "").lower()
        if tracker in allowed_tracker_ids_set:
            info_hash = torrent["InfoHash"]
            if info_hash not in files:
                found_uncached += 1
                torrent_data = {
                    "index": 1,
                    "title": torrent["Title"],
                    "size": torrent["Size"],
                    "uncached": True,
                    "link": torrent["Link"],
                    "magnet": torrent["MagnetUri"],
                    "seeders": torrent.get("Seeders", 0)
                }
                # Update files and serialize data for database insertion
                files[info_hash] = torrent_data
                torrent_data = json.dumps(torrent_data)
                uncached_torrents.append({
                    "hash": info_hash,
                    "torrentId": "",
                    "data": torrent_data,
                    "cacheKey": cache_key,
                    "timestamp": current_timestamp
                })

    # Batch insert uncached torrents
    if uncached_torrents:
        await database.execute_many(
            "INSERT OR IGNORE INTO uncached_torrents (hash, torrentId, data, cacheKey, timestamp) VALUES (:hash, :torrentId, :data, :cacheKey, :timestamp)",
            uncached_torrents
        )

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


def get_balanced_hashes(hashes: dict, config: dict):
    max_results = config["maxResults"]
    max_size = config["maxSize"]
    config_resolutions = config["resolutions"]
    config_resolutions_order = config.get("resolutionsOrder", [])
    config_languages = {
        language.replace("_", " ").capitalize() for language in config["languages"]
    }
    config_language_preference = {
        language.replace("_", " ").capitalize() for language in config["languagePreference"]
    }
    include_all_languages = "All" in config_languages
    include_all_resolutions = "All" in config_resolutions
    include_unknown_resolution = (
        include_all_resolutions or "Unknown" in config_resolutions
    )

    hashes_by_resolution = {}
    for hash, hash_data in hashes.items():
        hash_info = hash_data["data"]

        if max_size != 0 and hash_info["size"] > max_size:
            continue

        if (
            not include_all_languages
            and not hash_info["is_multi_audio"]
            and not any(lang in hash_info["language"] for lang in config_languages)
        ):
            continue

        resolution = hash_info["resolution"]
        if not resolution:
            if not include_unknown_resolution:
                continue
            resolution_key = "Unknown"
        else:
            resolution_key = resolution[0]
            if not include_all_resolutions and resolution_key not in config_resolutions:
                continue
        if "Uncached" in config["resolutionsOrder"] and "Sort_by_Rank" not in config["sortType"]:
            if hash_info.get("uncached", False):
                resolution_key = "Uncached"
        if resolution_key not in hashes_by_resolution:
            hashes_by_resolution[resolution_key] = []
        hashes_by_resolution[resolution_key].append(hash)

    # Sorting
    hashes_by_resolution = apply_sorting(
        hashes_by_resolution,
        hashes,
        config_resolutions_order,
        config_language_preference,
        config.get("sortType", "Sort_by_Rank")
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
            available_hashes = hash_list[current_count : current_count + missing_hashes]
            balanced_hashes[resolution].extend(available_hashes)
            missing_hashes -= len(available_hashes)

    return balanced_hashes


def apply_sorting(hashes_by_resolution, hashes, config_resolutions_order, config_languages_preference, sort_type):
    """Apply the specified sorting function based on the sort_type string. Sorts Uncached always by seeders"""
    # Create resolution index map for fast lookup
    resolution_index_map = {res: i for i, res in enumerate(config_resolutions_order or [
        "4K", "2160p", "1440p", "1080p", "720p", "576p", "480p", "360p", "Uncached", "Unknown"
    ])}

    # Only create the set if there is a language preference
    languages_set = set(config_languages_preference) if config_languages_preference else None

    def sort_by_resolution(res):
        """Sort by resolution based on the config order."""
        return resolution_index_map.get(res, len(config_resolutions_order))

    def sort_by_priority_language(hash_key):
        """Sort by priority language based on config_languages_preference."""
        languages = hashes[hash_key]["data"].get("language", [])
        return next((i for i, lang in enumerate(config_languages_preference) if lang in languages), len(config_languages_preference))

    def sort_uncached_by_seeders(sorted_hashes_by_resolution):
        """Ensure Uncached, if it exists, is always sorted by seeders."""
        if "Uncached" in sorted_hashes_by_resolution:
            sorted_hashes_by_resolution["Uncached"].sort(
                key=lambda hash_key: -int(hashes[hash_key]["data"].get("seeders", 0))
            )
        return sorted_hashes_by_resolution

    def sort_by_resolution_only():
        """Sort by resolution based on the config order, then sort Uncached by seeders."""
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        return sort_uncached_by_seeders(sorted_hashes_by_resolution)

    def sort_by_resolution_then_seeders():
        """Sort by resolution, then by seeders within each resolution, and always sort Uncached by seeders."""
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        for res, hash_list in sorted_hashes_by_resolution.items():
            hash_list.sort(key=lambda hash_key: -int(hashes[hash_key]["data"].get("seeders", 0)))
        return sort_uncached_by_seeders(sorted_hashes_by_resolution)

    def sort_by_resolution_then_size():
        """Sort by resolution, then by file size within each resolution, and always sort Uncached by seeders."""
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        for res, hash_list in sorted_hashes_by_resolution.items():
            hash_list.sort(key=lambda hash_key: -hashes[hash_key]["data"].get("size", 0))
        return sort_uncached_by_seeders(sorted_hashes_by_resolution)

    def prioritize_languages(sorted_hashes_by_resolution):
        """Prioritize torrents by languages according to config_languages_preference."""
        if not languages_set:
            return sorted_hashes_by_resolution  # No need to prioritize if there's no preference

        for res, hash_list in sorted_hashes_by_resolution.items():
            prioritized = [hash_key for hash_key in hash_list if languages_set.intersection(hashes[hash_key]["data"].get("language", []))]
            non_prioritized = [hash_key for hash_key in hash_list if hash_key not in prioritized]
            prioritized.sort(key=sort_by_priority_language)
            sorted_hashes_by_resolution[res] = prioritized + non_prioritized
        return sorted_hashes_by_resolution

    # Main sorting logic
    if sort_type == "Sort_by_Rank":
        sorted_hashes_by_resolution = hashes_by_resolution
    elif sort_type == "Sort_by_Resolution":
        sorted_hashes_by_resolution = sort_by_resolution_only()
    elif sort_type == "Sort_by_Resolution_then_Seeders":
        sorted_hashes_by_resolution = sort_by_resolution_then_seeders()
    elif sort_type == "Sort_by_Resolution_then_Size":
        sorted_hashes_by_resolution = sort_by_resolution_then_size()
    else:
        logger.warning(f"Invalid sort type, results will be sorted by rank")
        sorted_hashes_by_resolution = hashes_by_resolution

    # Apply language prioritization if needed
    if languages_set:
        logger.info(f"Sorting results by language Preference {config_languages_preference}")
        sorted_hashes_by_resolution = prioritize_languages(sorted_hashes_by_resolution)

    return sorted_hashes_by_resolution


def format_metadata(data: dict):
    extras = []
    if data["hdr"] != "":
        extras.append(data["hdr"] if data["hdr"] != "DV" else "Dolby Vision")
    if data["remux"]:
        extras.append("Remux")
    if data["proper"]:
        extras.append("Proper")
    if data["repack"]:
        extras.append("Repack")
    if data["upscaled"]:
        extras.append("Upscaled")
    if data["remastered"]:
        extras.append("Remastered")
    if data["directorsCut"]:
        extras.append("Director's Cut")
    if data["extended"]:
        extras.append("Extended")
    return " | ".join(extras)


async def get_localized_titles(languages, id: str, session: ClientSession):
    headers = {
        "content-type": "application/json"
    }
    params = {
        "operationName": "TitleAkasPaginated",
        "variables": f'{{"const":"{id}","first":8000}}',
        "extensions": '{"persistedQuery":{"sha256Hash":"48d4f7bfa73230fb550147bd4704d8050080e65fe2ad576da6276cac2330e446","version":1}}'
    }
    try:
        gathered_localized_titles = await session.get(f'https://caching.graphql.imdb.com/', params=params, headers=headers)
    except Exception as e:
        logger.warning(
            f"Exception while getting localized titles: {e}"
        )
        return []
    localized_titles = await gathered_localized_titles.json()

    return extract_localized_titles(localized_titles, languages)


def extract_localized_titles(data: dict, languages):
    results = {}
    # Loop through the edges in the JSON data
    for edge in data['data']['title']['akas']['edges']:
        node = edge['node']
        country_id = node['country']['id'].lower()

        # Check if the country id or language matches any of the passed languages
        if country_id in languages:
            title = node['displayableProperty']['value']['plainText']
            qualifiers = node['displayableProperty'].get('qualifiersInMarkdownList') or []

            # Check if any qualifier mentions "dubbed"
            is_dubbed = any("dubbed" in (qualifier.get('plainText', '').lower()) for qualifier in qualifiers)

            # Prioritize dubbed titles or store the title if no better alternative exists
            if is_dubbed or country_id not in results:
                results[country_id] = title
    return results


def format_title(data: dict, config: dict):
    title = ""
    logger.info(config)
    if "Title" in config["resultFormat"] or "All" in config["resultFormat"]:
        title += f"{data['title']}\n"
    if "Metadata" in config["resultFormat"] or "All" in config["resultFormat"]:
        metadata = format_metadata(data)
        if metadata != "":
            title += f"💿 {metadata}\n"
    if "Size" in config["resultFormat"] or "All" in config["resultFormat"]:
        title += f"💾 {bytes_to_size(data['size'])} "
    if "Tracker" in config["resultFormat"] or "All" in config["resultFormat"]:
        title += f"🔎 {data['tracker'] if 'tracker' in data else '?'}"
    if "Uncached" in config["resultFormat"] or "All" in config["resultFormat"]:
        if data.get("uncached", False):
            title += "\n" + f"⚠️ Uncached"
    if "Seeders" in config["resultFormat"] or "All" in config["resultFormat"] or data.get("uncached", True):
        if data.get('seeders', None) is not None:
            title += f"🌱 {data.get('seeders')} Seeders"
    if "Languages" in config["resultFormat"] or "All" in config["resultFormat"]:
        languages = data["language"]
        formatted_languages = (
            "/".join(get_language_emoji(language) for language in languages)
            if languages
            else get_language_emoji("multi_audio") if data["is_multi_audio"] else None
        )
        languages_str = "\n" + formatted_languages if formatted_languages else ""
        title += f"{languages_str}"
    if title == "":
        # Without this, Streamio shows SD as the result, which is confusing
        title = "Empty result format configuration"
    return title
