import PTT
import RTN
import random
import string

from fastapi import APIRouter, Request, HTTPException, Body
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from comet.utils.models import settings
from comet.utils.general import config_check, get_debrid_extension, short_encrypt, short_decrypt

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
languages = [language for language in PTT.parse.LANGUAGES_TRANSLATION_TABLE.values()]
languages.insert(0, "Unknown")
languages.insert(1, "Multi")
web_config = {
    "indexers": [indexer.replace(" ", "_").lower() for indexer in indexers],
    "languages": languages,
    "languagePreference": [
        language for language in PTT.parse.LANGUAGES_TRANSLATION_TABLE.values()
    ],
    "searchLanguage": [
        language for language in PTT.parse.LANGUAGES_TRANSLATION_TABLE.values()
    ],
    "resolutions": [resolution.value.capitalize() for resolution in RTN.models.Resolution] + ["Uncached"],
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
    "resultFormat": ["Title", "Metadata", "Size", "Tracker", "Uncached", "Seeders", "Complete", "Languages"],
    "sortType": ["Sort_by_Resolution_then_Rank", "Sort_by_Resolution_then_Seeders", "Sort_by_Resolution_then_Size"],
    "sortPreference": ["Completion", "Disabled"],
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
            if settings.CUSTOM_HEADER_HTML
            else "",
            "webConfig": web_config,
            "TOKEN": settings.TOKEN
            if settings.TOKEN else "",
            "URL_PREFIX": settings.URL_PREFIX
            if settings.URL_PREFIX else "",
            "indexerManager": settings.INDEXER_MANAGER_TYPE,
            "proxyDebridStream": settings.PROXY_DEBRID_STREAM,
        },
    )


@main.post("/configure", response_class=JSONResponse)
async def configure_post(data: str = Body(..., embed=True), action: str = Body(..., embed=True)):
    if not settings.TOKEN:
        raise HTTPException(status_code=400, detail="Encryption key not set")

    try:
        if action == "encrypt":
            result = short_encrypt(data, settings.TOKEN)
        elif action == "decrypt":
            result = short_decrypt(data, settings.TOKEN)
        else:
            raise HTTPException(status_code=400, detail="Invalid action")

        return JSONResponse(content={"result": result})
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@main.get("/manifest.json")
@main.get("/{b64config}/manifest.json")
async def manifest(b64config: str = None):
    config = config_check(b64config)
    if not config:
        config = {"debridService": None}

    debrid_extension = get_debrid_extension(config["debridService"])

    return {
        "id": f"{settings.ADDON_ID}.{''.join(random.choice(string.ascii_letters) for _ in range(4))}",
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
