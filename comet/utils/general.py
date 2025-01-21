import base64
import hashlib
import os
import re
import zlib
from typing import Literal, List, Union, Callable, Any

import PTT
import aiohttp
import bencodepy
import asyncio
import orjson
import time
import copy

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
from comet.utils.models import database, settings, ConfigModel

languages_emojis = {
    "unknown": "❓",  # Unknown
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
extra_file_pattern = re.compile(r"\b(sample|ncop|nced|op|ed|extras|special|omake|ova|ona|oad|pv|cm|promo|trailer|preview|teaser|creditless|behind[ _-]?the[ _-]?scenes|making[ _-]?of|deleted[ _-]?scenes)\b", re.IGNORECASE)


catalog_config = {
    "realdebrid": {
        "amount": 500,
        "preview_filter": lambda files: [file for file in files if file.get('Status') == "downloaded"],
        "meta_filter": lambda files: [file for file in files if file.get('selected') != "0" and is_video(file.get('path'))],
        "files_getter": lambda torrent: torrent.get("files"),
        "title_getter": lambda torrent: torrent.get("filename"),
        "torrent_id_getter": lambda torrent: torrent.get("id"),
        "file_id_getter": lambda file, i: file.get("id"),
        "file_name_getter": lambda file: file.get("path"),
        "hash_getter": lambda torrent: torrent.get("hash"),
    },
    "debridlink": {
        "amount": 50,
        "preview_filter": lambda files: [file for file in files if int(file.get('Status')) == 100],
        "meta_filter": lambda files: [file for file in files if int(file.get('downloadPercent')) == 100 and is_video(file.get('name'))],
        "files_getter": lambda torrent: torrent.get("value")[0].get("files"),
        "title_getter": lambda torrent: torrent.get("value")[0].get("name"),
        "torrent_id_getter": lambda torrent: torrent.get("value")[0].get("id"),
        "file_id_getter": lambda file, i: i,
        "file_name_getter": lambda file: file.get("name"),
        "hash_getter": lambda torrent: torrent.get("value")[0].get("hashString"),
    },
    "alldebrid": {
        "amount": 100,
        "preview_filter": lambda files: [file for file in files if file.get('Status') == "Ready"],
        "meta_filter": lambda files: [file for file in files if is_video(file.get('filename'))],
        "files_getter": lambda torrent: torrent.get("data").get("magnets").get("links"),
        "title_getter": lambda torrent: torrent.get("data").get("magnets").get("filename"),
        "torrent_id_getter": lambda torrent: str(torrent.get("data").get("magnets").get("id")),
        "file_id_getter": lambda file, i: i,
        "file_name_getter": lambda file: file.get("filename"),
        "hash_getter": lambda torrent: torrent.get("data").get("magnets").get("hash"),
    },
    "torbox": {
        "amount": 1000,
        "preview_filter": lambda files: [file for file in files if file.get('Status') == "cached" or file.get('Status') == "uploading" or file.get('Status') == "completed"],
        "meta_filter": lambda files: [file for file in files if is_video(file.get('name'))],
        "files_getter": lambda torrent: torrent.get("data").get("files"),
        "title_getter": lambda torrent: torrent.get("data").get("name"),
        "torrent_id_getter": lambda torrent: str(torrent.get("data").get("id")),
        "file_id_getter": lambda file, i: file.get("id"),
        "file_name_getter": lambda file: file.get("name"),
        "hash_getter": lambda torrent: torrent.get("data").get("hash"),
    }
}


def translate(title: str):
    return title.translate(translation_table)


def clean_titles(torrent_name):
    """
    Extracts the main title from a torrent name by removing tags, subtitles, and additional information.
    Captures the title up to the first delimiter like `[`, `(`, `|`, `/`, or `-`.
    """
    match = re.search(r'^[^\[\]\(\)]*?([A-Za-z0-9\s\']+?)(?=\s*[\[\(\|/-])', torrent_name)
    return match.group(1).strip() if match else torrent_name.strip()


VIDEO_FILE_EXTENSIONS = [
    ".3g2",".3gp",".amv",".asf",".avi",".drc",".f4a",".f4b",".f4p",".f4v",
    ".flv",".gif",".gifv",".m2v",".m4p",".m4v",".mkv",".mov",".mp2",".mp4",
    ".mpg",".mpeg",".mpv",".mng",".mpe",".mxf",".nsv",".ogg",".ogv",".qt",
    ".rm",".rmvb",".roq",".svi",".webm",".wmv",".yuv"
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


def derive_debrid_key(debrid_key: str):
    return hashlib.sha256(debrid_key.encode()).hexdigest()


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
        orjson.loads(base64.b64decode(s + '=' * (-len(s) % 4)).decode())
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
            config = orjson.loads(short_decrypt(config_data, settings.TOKEN))
        else:
            config = orjson.loads(base64.b64decode(config_data + '=' * (-len(config_data) % 4)).decode())
        validated_config = ConfigModel(**config)
        return validated_config.model_dump()
    except Exception as e:
        logger.error(f"Error checking config: {e}")
        return False


def size_to_bytes(size_str: str):
    sizes = ["bytes", "kb", "mb", "gb", "tb"]
    try:
        value, unit = size_str.split()
        value = float(value)
        unit = unit.lower()

        if unit not in sizes:
            return None

        multiplier = 1024 ** sizes.index(unit)
        return int(value * multiplier)
    except:
        return None


def get_debrid_extension(debridService: str, debridApiKey: str = None):
    if debridApiKey == "":
        return "TORRENT"

    debrid_extensions = {
        "realdebrid": "RD",
        "alldebrid": "AD",
        "premiumize": "PM",
        "torbox": "TB",
        "debridlink": "DL",
    }

    return debrid_extensions.get(debridService, None)


def build_custom_filename(parsed_data: dict):
    fields_order = [
        "normalized_title",
        "group",
        "resolution",
        "quality",
        "languages",
        "codec",
        "audio",
        "channels",
        "network",
        "hdr",
        "audio",
        "year"
    ]
    parts = []
    for field in fields_order:
        if field not in parsed_data:
            continue
        value = parsed_data[field]
        if not value:
            continue
        if isinstance(value, list):
            joined = ".".join(str(item) for item in value)
            if joined:
                parts.append(joined)
        else:
            parts.append(str(value))
    filename = ".".join(parts)
    return filename


async def get_indexer_manager(
        session: aiohttp.ClientSession,
        indexer_manager_type: str,
        indexers: list,
        query: str,
        config: dict,
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
                    (indexer["protocol"] != "usenet" or config["debridService"] == "torbox")
                    and (
                    indexer["name"].lower() in indexers
                    or indexer["definitionName"].lower() in indexers
                    )
                ):
                    indexers_id.append(indexer["id"])

            response = await session.get(
                f"{settings.INDEXER_MANAGER_URL}/api/v1/search?query={query}&indexerIds={'&indexerIds='.join(str(indexer_id) for indexer_id in indexers_id)}&type=search&limit=500000",
                headers={"X-Api-Key": settings.INDEXER_MANAGER_API_KEY},
            )
            response = await response.json()

            for result in response:
                result["InfoHash"] = (
                    result["infoHash"] if "infoHash" in result else None
                )
                if result["protocol"] == "usenet" and result["InfoHash"] is None:
                    result["InfoHash"] = hashlib.sha1(result["fileName"].encode('utf-8')).hexdigest()
                result["Title"] = result["title"]
                result["Size"] = result["size"]
                result["Link"] = (
                    result["downloadUrl"] if "downloadUrl" in result else None
                )
                result["Tracker"] = result["indexer"]
                result["Protocol"] = result["protocol"]

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
                    "Size": int(result["size"]),
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
            title_full = torrent["title"]
            title = title_full.split("\n")[0]
            tracker = title_full.split("⚙️ ")[1].split("\n")[0]
            size = size_to_bytes(title_full.split("💾 ")[1].split(" ⚙️")[0])
            seeders = int(title_full.split("👤")[1].split()[0])


            results.append(
                {
                    "Title": title,
                    "InfoHash": torrent["infoHash"],
                    "Size": size,
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


async def get_mediafusion(log_name: str, type: str, full_id: str):
    results = []
    try:
        try:
            get_mediafusion = requests.get(
                f"{settings.MEDIAFUSION_URL}/stream/{type}/{full_id}.json"
            ).json()
        except:
            get_mediafusion = requests.get(
                f"{settings.MEDIAFUSION_URL}/stream/{type}/{full_id}.json",
                proxies={
                    "http": settings.DEBRID_PROXY_URL,
                    "https": settings.DEBRID_PROXY_URL,
                },
            ).json()

        for torrent in get_mediafusion["streams"]:
            title_full = torrent["description"]
            title = title_full.split("\n")[0].replace("📂 ", "").replace("/", "")
            tracker = title_full.split("🔗 ")[1]

            results.append(
                {
                    "Title": title,
                    "InfoHash": torrent["infoHash"],
                    "Size": torrent["behaviorHints"][
                        "videoSize"
                    ],  # not the pack size but still useful for prowlarr userss
                    "Tracker": f"MediaFusion|{tracker}",
                }
            )

        logger.info(f"{len(results)} torrents found for {log_name} with MediaFusion")

    except Exception as e:
        logger.warning(
            f"Exception while getting torrents for {log_name} with MediaFusion, your IP is most likely blacklisted (you should try proxying Comet): {e}"
        )
        pass

    return results


async def filter(
    torrents: list,
    title_list: list,
    season: int,
    year: int,
    year_end: int,
    aliases: dict,
    remove_adult_content: bool,
):
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
            if remove_adult_content and parsed.adult:
                results.append((index, False))
                continue

            if name in parsed.raw_title and check_completion(parsed.raw_title, season):
                results.append((index, True))
                continue

            parsed.parsed_title = clean_titles(parsed.parsed_title)
            if parsed.parsed_title and not title_match(
                    name, parsed.parsed_title, aliases=aliases
            ):
                results.append((index, False))
                continue

            if year and parsed.year:
                if year_end is not None:
                    if not (year <= parsed.year <= year_end):
                        results.append((index, False))
                        continue
                else:
                    if year < (parsed.year - 1) or year > (parsed.year + 1):
                        results.append((index, False))
                        continue

            results.append((index, True))

    return results


async def uncached_select_index(
        files: List[dict],
        index: Union[int, str],
        name: str,
        episode: str,
        season: str,
        torrent_parsed_data: str,
        debrid_service: str
) -> Union[int, str]:
    """
    Select the appropriate file index or ID from a list of files based on matching titles.

    :param files: List of files from the magnet info.
    :param search_title: Title to search for in the file names.
    :param index: Default fallback index if no match is found.
    :param debridservice: The debrid service being used.
    :return: The selected file ID or index depending on the service.
    """

    # Service-specific configurations
    service_config = {
        "realdebrid": {
            "file_name_extractor": lambda file: file.get("path", "").split("/")[-1],
            "filter": lambda files: [file for file in files if file.get('selected') != 0],
            "id_getter": lambda file, i: file.get("id"),
            "fallback": lambda idx: int(idx) + 1,
        },
        "debridlink": {
            "file_name_extractor": lambda file: file.get("name", ""),
            "filter": lambda files: files,  # No filtering for DL
            "id_getter": lambda file, i: i,
            "fallback": lambda idx: max(int(idx) - 1, 0),
        },
        "alldebrid": {
            "file_name_extractor": lambda file: file.get("filename", ""),
            "filter": lambda files: files,
            "id_getter": lambda file, i: i,
            "fallback": lambda idx: max(int(idx) - 1, 0),
        },
        "premiumize": {
            "file_name_extractor": lambda file: file.get("path", "").split("/")[-1],
            "filter": lambda files: files,
            "id_getter": lambda file, i: i,
            "fallback": lambda idx: max(int(idx) - 1, 0),
        },
        "torbox": {
            "file_name_extractor": lambda file: file.get("short_name", ""),
            "filter": lambda files: files,
            "id_getter": lambda file, i: file.get("id"),
            "fallback": lambda idx: max(int(idx) - 1, 0),
        },
    }

    # Ensure service is supported
    if debrid_service not in service_config:
        raise Exception(f"Unsupported debrid service: {debrid_service}")
    # Ensure files list has files
    if len(files) <= 0:
        raise Exception(f"Exception while checking files, no files found, torrent might be stale, for {debrid_service} | {name}")

    # Get the config for the selected service
    config = service_config[debrid_service]
    file_name_extractor: Callable[[dict], str] = config["file_name_extractor"]
    file_filter: Callable[[List[dict]], List[dict]] = config["filter"]
    id_getter: Callable[[dict, int], Any] = config["id_getter"]
    fallback: Callable[[int], Any] = config["fallback"]
    selected_id_or_index = None

    # Apply the service-specific filter
    files = file_filter(files)

    # Return early if only one file in torrent
    if len(files) == 1:
        selected_id_or_index = fallback(0)
        return selected_id_or_index

    # Match based on parsed episode or year/res for movies
    torrent_parsed_data = orjson.loads(torrent_parsed_data)

    for i, file in enumerate(files):
        file_name = file_name_extractor(file)
        if extra_file_pattern.search(file_name) or not is_video(file_name):
            continue
        file_name_parsed = parse(file_name)

        if episode:
            if len(file_name_parsed.episodes) > 0 and file_name_parsed.episodes[0] == int(episode):
                if len(file_name_parsed.seasons) > 0 and int(season) in file_name_parsed.seasons:
                    selected_id_or_index = id_getter(file, i)
                    break
                selected_id_or_index = id_getter(file, i)

        # Check in case movie. Uncached movies have always index 0 as placeholder. Shows index > 0 (index = episode)
        if (
                (int(index) == 0 and file_name_parsed.normalized_title == torrent_parsed_data["data"]["normalized_title"])
                or
                (int(index) == 0 and clean_titles(file_name_parsed.normalized_title) == clean_titles(torrent_parsed_data["data"]["normalized_title"]))
        ):
            selected_id_or_index = id_getter(file, i)
            break

    # Fallback: Use service-specific fallback logic
    if selected_id_or_index is None:
        if int(index) > len(files)-1:
            index = 0
        selected_id_or_index = fallback(index)
        logger.warning(
            f"Exception while selecting files, could not identify correct video file, using fallback, for {debrid_service} | {name}"
        )
    return selected_id_or_index


async def uncached_db_find_container_id(debrid_key: str, hash: str) -> str:
    """
    Returns first found containerId for the given hash.
    If returned string not empty caching to debrid has been started.
    If containerId not empty no need for additional download start of this hash.
    """
    query = """
    SELECT container_id
    FROM cache
    WHERE debrid_key = :debrid_key AND info_hash = :hash AND container_id != ''
    """
    result = await database.fetch_one(query, {"hash": hash, "debrid_key": debrid_key})
    if result:
        return result["container_id"]
    else:
        return ""


async def update_torrent_id_uncached_db(debrid_key: str, hash: str, file_index: str, torrent_id: str):
    """
    Sets the Torrent Id for one specific file / uncached torrent
    """
    query = """
    UPDATE cache 
    SET torrent_id = :torrent_id
    WHERE debrid_key = :debrid_key AND info_hash = :hash AND file_index = :file_index
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
    UPDATE cache 
    SET container_id = :container_id
    WHERE debrid_key = :debrid_key AND info_hash = :hash
    """
    await database.execute(query, {
        "container_id": container_id,
        "debrid_key": debrid_key,
        "hash": hash
    })


async def check_index(hash: str, file_index: str, debrid_key: str):
    """
    Checks if torrent has a torrent_id assigned and returns it
    """
    uncached_torrent = await database.fetch_one(
        """
        SELECT torrent_id
        FROM cache
        WHERE debrid_key = :debrid_key AND info_hash = :hash AND file_index = :file_index
        """,
        {"debrid_key": debrid_key, "hash": hash, "file_index": file_index}
    )
    if uncached_torrent:
        if uncached_torrent["torrent_id"] and int(uncached_torrent["torrent_id"]) >= 0:
            return uncached_torrent["torrent_id"]
        else:
            return file_index
    else:
        return file_index


async def check_uncached(hash: str, file_index: str, debrid_key: str):
    # Fetch uncached torrent data from the database
    uncached_torrent = await database.fetch_one(
        """
        SELECT torrent_id, container_id, link, magnet, data, name, raw_title, episode, season, protocol
        FROM cache
        WHERE debrid_key = :debrid_key AND info_hash = :hash AND file_index = :file_index AND uncached = :uncached
        """,
        {"debrid_key": debrid_key, "hash": hash, "file_index": file_index, "uncached": True}
    )

    if uncached_torrent:
        # Check if the magnet key exists and is not empty/None
        has_magnet = bool(uncached_torrent["magnet"])

        return {
            "name": uncached_torrent["name"],
            "raw_title": uncached_torrent["raw_title"],
            "episode": uncached_torrent["episode"],
            "season": uncached_torrent["season"],
            "parsed_data": uncached_torrent["data"],
            "torrent_id": uncached_torrent["torrent_id"],
            "container_id": uncached_torrent["container_id"],
            "torrent_link": uncached_torrent["link"],
            "protocol": uncached_torrent["protocol"],
            "has_magnet": has_magnet
        }
    else:
        return None


async def update_uncached_status(uncached: bool, hash: str, file_index: str, debridService: str, debrid_key: str):
    """
    Updates the uncached flag in both the database column and JSON data field.
    """
    # Fetch and update JSON data
    updater = await database.fetch_one(
        "SELECT torrent_id FROM cache WHERE info_hash = :hash AND file_index = :file_index AND debridService = :debridService AND debrid_key = :debrid_key",
        {"hash": hash, "file_index": file_index, "debridService": debridService, "debrid_key": debrid_key}
    )
    rows = await database.fetch_all(
        "SELECT data FROM cache WHERE info_hash = :hash AND file_index = :file_index AND debridService = :debridService",
        {"hash": hash, "file_index": file_index, "debridService": debridService}
    )
    if not rows or not updater:
        # Return as it probably was a cached torrent being played
        return

    updates_to_execute = []
    for row in rows:
        parsed_data = orjson.loads(row["data"])
        parsed_data["data"]["uncached"] = uncached
        updates_to_execute.append({
            "info_hash": hash,
            "file_index": file_index,
            "torrent_id": updater["torrent_id"],
            "debridService": debridService,
            "uncached": uncached,
            "updated_data": orjson.dumps(parsed_data).decode("utf-8"),
        })

    if updates_to_execute:
        await database.execute_many(
            """
            UPDATE cache 
            SET uncached = :uncached, data = :updated_data, torrent_id = :torrent_id
            WHERE info_hash = :info_hash AND file_index = :file_index AND debridService = :debridService
            """,
            updates_to_execute
        )
    else:
        logger.error(f"Error could not update uncached torrents.")
        return


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

    logger.warning(f"Cache cleanup completed. Total entries deleted: {result_cache}")


async def add_uncached_files(
        files: dict,
        torrents: list,
        log_name: str,
        allowed_tracker_ids: list,
        season: int,
        episode: int,
        kitsu: bool,
):
    allowed_tracker_ids_set = {tracker_id.lower() for tracker_id in allowed_tracker_ids}
    found_uncached = 0

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
                file_index = episode if episode else 0
                stremio_data = {
                    "index": file_index,
                    "title": torrent["Title"],
                    "size": torrent.get("Size") if torrent.get("Size") is not None else 0,
                    "uncached": True,
                    "complete": None,
                    "seeders": torrent.get("Seeders") if torrent.get("Seeders") is not None else 0
                }
                # Update files used for stremio
                files[info_hash] = stremio_data

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
    max_results_per_resolution = config["maxResultsPerResolution"]

    max_size = config["maxSize"]
    config_resolutions = [resolution for resolution in config["resolutions"]]
    include_all_resolutions = "All" in config_resolutions
    remove_trash = config["removeTrash"]

    config_resolutions_order = config.get("resolutionsOrder", [])
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
        if remove_trash and not hash_data["fetch"]:
            continue

        hash_info = hash_data["data"]

        if max_size != 0 and hash_info["size"] > max_size:
            continue

        if (
            not include_all_languages
            and not any(lang in hash_info["languages"] for lang in config_languages)
            and ("multi" not in languages if hash_info["dubbed"] else True)
            and not (len(hash_info["languages"]) == 0 and "unknown" in languages)
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

    if config["reverseResultOrder"]:
        hashes_by_resolution = {
            res: lst[::-1] for res, lst in hashes_by_resolution.items()
        }

    total_resolutions = len(hashes_by_resolution)
    if max_results == 0 and max_results_per_resolution == 0 or total_resolutions == 0:
        return hashes_by_resolution

    hashes_per_resolution = (
        max_results // total_resolutions
        if max_results > 0
        else max_results_per_resolution
    )
    extra_hashes = max_results % total_resolutions

    balanced_hashes = {}
    for resolution, hash_list in hashes_by_resolution.items():
        selected_count = hashes_per_resolution + (1 if extra_hashes > 0 else 0)
        if max_results_per_resolution > 0:
            selected_count = min(selected_count, max_results_per_resolution)
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

    def sort_by_resolution(res):
        return resolution_index_map.get(res, len(config_resolutions_order))

    def sort_by_resolution_then_rank():
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        for res, hash_list in sorted_hashes_by_resolution.items():
            hash_list.sort(key=lambda hash_key: (
            -int(hashes[hash_key]["data"].get("rank", 0)), -hashes[hash_key]["data"].get("size", 0)))
        return sorted_hashes_by_resolution

    def sort_by_resolution_then_seeders():
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        for res, hash_list in sorted_hashes_by_resolution.items():
            hash_list.sort(key=lambda hash_key: -int(hashes[hash_key]["data"].get("seeders", 0)))
        return sorted_hashes_by_resolution

    def sort_by_resolution_then_size():
        sorted_hashes_by_resolution = {
            k: v for k, v in sorted(hashes_by_resolution.items(), key=lambda item: sort_by_resolution(item[0]))
        }
        for res, hash_list in sorted_hashes_by_resolution.items():
            hash_list.sort(key=lambda hash_key: -hashes[hash_key]["data"].get("size", 0))
        return sorted_hashes_by_resolution

    def prioritize_languages(sorted_hashes_by_resolution):
        """Prioritize torrents by languages according to config_languages_preference."""
        if not config_languages_preference:
            return sorted_hashes_by_resolution
        # Get language codes for the configured language preferences
        language_codes = get_language_codes(config_languages_preference)
        # Build a priority map for the language codes
        language_priority = {lang: i for i, lang in enumerate(language_codes)}
        for res, hash_list in sorted_hashes_by_resolution.items():
            # Sort items based on language priority
            sorted_hashes_by_resolution[res] = sorted(
                hash_list,
                key=lambda hash_key: (
                    language_priority.get(
                        next(
                            (lang for lang in hashes[hash_key]["data"].get("languages", []) if lang in language_priority),
                            None,
                        ),
                        float("inf"),
                    ),
                    hash_list.index(hash_key),  # Preserve relative order for identical languages
                ),
            )
        return sorted_hashes_by_resolution

    def prioritize_cached(sorted_hashes_by_resolution):
        """Move uncached items to the bottom of each resolution group."""
        for res, hash_list in sorted_hashes_by_resolution.items():
            # Separate cached and uncached
            cached = [hash_key for hash_key in hash_list if not hashes[hash_key]["data"].get("uncached", False)]
            uncached = [hash_key for hash_key in hash_list if hash_key not in cached]
            # Merge and update
            sorted_hashes_by_resolution[res] = cached + uncached
        return sorted_hashes_by_resolution

    def prioritize_completion(sorted_hashes_by_resolution):
        if type != "series":
            return sorted_hashes_by_resolution
        for res, hash_list in sorted_hashes_by_resolution.items():
            complete = [hash_key for hash_key in hash_list if hashes[hash_key]["data"].get("complete", False)]
            incomplete = [hash_key for hash_key in hash_list if hash_key not in complete]
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

    # Apply cached prioritization if needed
    if not hashes_by_resolution.get("Uncached", False):
        logger.info("Sorting results to prioritize cached torrents")
        sorted_hashes_by_resolution = prioritize_cached(sorted_hashes_by_resolution)

    # Apply language prioritization if needed
    if config_languages_preference and len(config_languages_preference) > 0:
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


async def search_imdb_id(search_query: str, session: ClientSession):
    headers = {
        "content-type": "application/json"
    }
    params = {
        "operationName": "AdvancedTitleSearch",
        "variables": f'{{"first":2,"locale":"en-GB","sortBy":"POPULARITY","sortOrder":"ASC","titleTextConstraint":{{"searchTerm":"{search_query}"}}}}',
        "extensions": '{"persistedQuery":{"sha256Hash":"60a7b8470b01671336ffa535b21a0a6cdaf50267fa2ab55b3e3772578a8c1f00","version":1}}'
    }
    try:
        gathered_results = await session.get(f'https://caching.graphql.imdb.com/', params=params, headers=headers)
        result = await gathered_results.json()
        if not result or result["data"]["advancedTitleSearch"]["total"] == 0:
            logger.warning(
                f"Exception while searching for imdb id"
            )
            return None

        main_data = result["data"]["advancedTitleSearch"]["edges"][0]["node"]["title"]

        title = main_data["titleText"]["text"]
        imdb_id = main_data["id"]
        poster = main_data["primaryImage"]["url"]
        description = main_data["plot"]["plotText"]["plainText"]
        imdbRating = main_data["ratingsSummary"]["aggregateRating"]
        startYear = main_data["releaseYear"]["year"]
        endYear = main_data["releaseYear"]["endYear"] if main_data["releaseYear"]["endYear"] else ""
        type = main_data["titleType"]["id"]
        genres = []
        if main_data["titleGenres"] and main_data["titleGenres"]["genres"] and len(main_data["titleGenres"]["genres"]) > 0:
            for genre in main_data["titleGenres"]["genres"]:
                genres.append(genre["genre"]["text"])

        return {
            "id": imdb_id,
            "title": title,
            "poster": poster,
            "description": description,
            "imdbRating": imdbRating,
            "genres": genres,
            "startYear": startYear,
            "endYear": endYear,
            "type": type
        }

    except Exception as e:
        logger.warning(
            f"Exception while searching imdb: {e}"
        )
        return None


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
        return {}
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
    result_format = config["resultFormat"]
    has_all = "All" in result_format

    title = ""
    if has_all or "Title" in result_format:
        title += f"{data['title']}\n"

    if has_all or "Metadata" in result_format:
        metadata = format_metadata(data)
        if metadata != "":
            title += f"💿 {metadata}\n"

    if has_all or "Uncached" in result_format:
        if data.get("uncached", False):
            title += f"⚠️ Uncached"

    if has_all or "Size" in result_format:
        title += f"💾 {bytes_to_size(data['size'])} "

    if has_all or "Seeders" in result_format or data.get("uncached", True):
        if data.get('seeders', None) is not None:
            title += f"🌱 {data.get('seeders')}"

    if has_all or "Tracker" in result_format:
        title += f"🔎 {data['tracker'].capitalize() if 'tracker' in data else '?'}"

    if has_all or "Complete" in result_format:
        if data.get("complete", False):
            title += f"📦 Complete Season"

    if has_all or "Languages" in result_format:
        languages = data["languages"]
        if data["dubbed"]:
            languages.insert(0, "multi")
        if languages:
            formatted_languages = "/".join(
                get_language_emoji(language) for language in languages
            )
            languages_str = "\n" + formatted_languages
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


async def add_torrent_to_cache(
    config: dict, name: str, season: int, episode: int, sorted_ranked_files: dict
):
    # trace of which indexers were used when cache was created - not optimal
    indexers = config["indexers"].copy()
    if settings.SCRAPE_TORRENTIO:
        indexers.append("torrentio")
    if settings.SCRAPE_MEDIAFUSION:
        indexers.append("mediafusion")
    if settings.ZILEAN_URL:
        indexers.append("dmm")
    if settings.DEBRID_TAKE_FIRST > 0:
        indexers.append(config["debridService"])
    for indexer in indexers:
        hash = f"searched-{indexer}-{name}-{season}-{episode}"

        searched = copy.deepcopy(
            sorted_ranked_files[list(sorted_ranked_files.keys())[0]]
        )
        searched["infohash"] = hash
        searched["data"]["tracker"] = indexer

        sorted_ranked_files[hash] = searched
    values = [
        {
            "debridService": config["debridService"],
            "info_hash": sorted_ranked_files[torrent]["infohash"],
            "debrid_key": derive_debrid_key(config["debridApiKey"]) if sorted_ranked_files[torrent]["data"]["uncached"] else '',
            "name": name,
            "raw_title": sorted_ranked_files[torrent]["raw_title"],
            "season": season,
            "episode": episode,
            "file_index": sorted_ranked_files[torrent]["data"]["index"],
            "torrent_id": sorted_ranked_files[torrent]["data"]["torrent_id"],
            "container_id": sorted_ranked_files[torrent]["data"]["container_id"],
            "uncached": sorted_ranked_files[torrent]["data"]["uncached"],
            "link": sorted_ranked_files[torrent]["data"]["link"],
            "magnet": sorted_ranked_files[torrent]["data"]["magnet"],
            "protocol": sorted_ranked_files[torrent]["data"]["protocol"],
            "tracker": sorted_ranked_files[torrent]["data"]["tracker"].split("|")[0].lower(),
            "data": orjson.dumps(sorted_ranked_files[torrent]).decode("utf-8"),
            "timestamp": time.time(),
        }
        for torrent in sorted_ranked_files
    ]

    query = f"""
        INSERT {'OR IGNORE ' if settings.DATABASE_TYPE == 'sqlite' else ''}
        INTO cache (debridService, info_hash, debrid_key, name, raw_title, season, episode, file_index, torrent_id, container_id, uncached, link, magnet, tracker, protocol, data, timestamp)
        VALUES (:debridService, :info_hash, :debrid_key, :name, :raw_title, :season, :episode, :file_index, :torrent_id, :container_id, :uncached, :link, :magnet, :tracker, :protocol, :data, :timestamp)
        {' ON CONFLICT DO NOTHING' if settings.DATABASE_TYPE == 'postgresql' else ''}
    """

    await database.execute_many(query, values)
