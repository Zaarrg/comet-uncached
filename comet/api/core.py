import RTN

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from comet.utils.models import settings
from comet.utils.general import config_check, get_debrid_extension

templates = Jinja2Templates("comet/templates")
main = APIRouter(prefix=f"{settings.URL_PREFIX}")


@main.get("/", status_code=200)
async def root(request: Request):
    redirect_path = request.url_for('configure')
    return RedirectResponse(redirect_path)


@main.get("/health", status_code=200)
async def health():
    return {"status": "ok"}


indexers = settings.INDEXER_MANAGER_INDEXERS
web_config = {
    "indexers": [indexer.replace(" ", "_").lower() for indexer in indexers],
    "languages": [
        language.replace(" ", "_")
        for language in RTN.patterns.language_code_mapping.keys()
    ],
    "languagePreference": [
        language.replace(" ", "_")
        for language in RTN.patterns.language_code_mapping.keys()
    ],
    "searchLanguage": [
        language.replace(" ", "_")
        for language in RTN.patterns.language_code_mapping.keys()
        if language.lower() not in ["multi subs", "multi audio", "dual audio"]
    ],
    "resolutions": [
        "360p",
        "480p",
        "576p",
        "720p",
        "1080p",
        "1440p",
        "2160p",
        "4K",
        "Unknown",
    ],
    "resultOrder": [
        "4K",
        "2160p",
        "1440p",
        "1080p",
        "720p",
        "576p",
        "480p",
        "360p",
        "Uncached",
        "Unknown",
    ],
    "resultFormat": ["Title", "Metadata", "Size", "Tracker", "Uncached", "Seeders", "Languages"],
    "sortType": ["Sort_by_Rank", "Sort_by_Resolution", "Sort_by_Resolution_then_Seeders", "Sort_by_Resolution_then_Size"],
    "urlPrefix": settings.URL_PREFIX if settings.URL_PREFIX else "",
}

@main.get("/configure")
@main.get("/{b64config}/configure")
async def configure(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "CUSTOM_HEADER_HTML": settings.CUSTOM_HEADER_HTML
            if settings.CUSTOM_HEADER_HTML and settings.CUSTOM_HEADER_HTML != "None"
            else "",
            "webConfig": web_config,
            "proxyDebridStream": settings.PROXY_DEBRID_STREAM,
        },
    )


@main.get("/manifest.json")
@main.get("/{b64config}/manifest.json")
async def manifest(b64config: str = None):
    config = config_check(b64config)
    if not config:
        config = {"debridService": None}

    debrid_extension = get_debrid_extension(config["debridService"])

    return {
        "id": settings.ADDON_ID,
        "name": f"{settings.ADDON_NAME}{(' | ' + debrid_extension) if debrid_extension is not None else ''}",
        "description": "Stremio's fastest torrent/debrid search add-on.",
        "version": "1.0.0",
        "catalogs": [],
        "resources": [
            {
                "name": "stream",
                "types": ["movie", "series"],
                "idPrefixes": ["tt", "kitsu"],
            }
        ],
        "types": ["movie", "series", "anime", "other"],
        "logo": "https://i.imgur.com/jmVoVMu.jpeg",
        "background": "https://i.imgur.com/WwnXB3k.jpeg",
        "behaviorHints": {"configurable": True, "configurationRequired": False},
    }
