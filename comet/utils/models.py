import os
import random
import string

from typing import List, Optional
from databases import Database
from pydantic import BaseModel, field_validator, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from RTN import RTN, BestRanking, SettingsModel


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    ADDON_ID: Optional[str] = "stremio.comet.fast"
    ADDON_NAME: Optional[str] = "Comet"
    FASTAPI_HOST: Optional[str] = "0.0.0.0"
    FASTAPI_PORT: Optional[int] = 8000
    FASTAPI_WORKERS: Optional[int] = 2 * (os.cpu_count() or 1)
    DASHBOARD_ADMIN_PASSWORD: Optional[str] = None
    DATABASE_TYPE: Optional[str] = "sqlite"
    DATABASE_URL: Optional[str] = "username:password@hostname:port"
    DATABASE_PATH: Optional[str] = "data/comet.db"
    CACHE_TTL: Optional[int] = 86400
    UNCACHED_TTL: Optional[int] = 43200
    CACHE_WIPE: Optional[int] = 172800
    CACHE_WIPE_TTL: Optional[int] = 86400
    DEBRID_PROXY_URL: Optional[str] = None
    INDEXER_MANAGER_TYPE: Optional[str] = "jackett"
    INDEXER_MANAGER_URL: Optional[str] = "http://127.0.0.1:9117"
    INDEXER_MANAGER_API_KEY: Optional[str] = None
    INDEXER_MANAGER_TIMEOUT: Optional[int] = 30
    INDEXER_MANAGER_INDEXERS: List[str] = ["EXAMPLE1_CHANGETHIS", "EXAMPLE2_CHANGETHIS"]
    GET_TORRENT_TIMEOUT: Optional[int] = 5
    ZILEAN_URL: Optional[str] = None
    ZILEAN_TAKE_FIRST: Optional[int] = 500
    DEBRID_TAKE_FIRST: Optional[int] = 0
    SCRAPE_TORRENTIO: Optional[bool] = False
    CUSTOM_HEADER_HTML: Optional[str] = None
    PROXY_DEBRID_STREAM: Optional[bool] = False
    PROXY_DEBRID_STREAM_PASSWORD: Optional[str] = None
    PROXY_DEBRID_STREAM_MAX_CONNECTIONS: Optional[int] = 100
    PROXY_DEBRID_STREAM_DEBRID_DEFAULT_SERVICE: Optional[str] = "realdebrid"
    PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY: Optional[str] = None
    TITLE_MATCH_CHECK: Optional[bool] = True
    URL_PREFIX: Optional[str] = ""
    TOKEN: Optional[str] = ""

    @field_validator("DASHBOARD_ADMIN_PASSWORD")
    def set_dashboard_admin_password(cls, v, values):
        if v is None:
            return "".join(random.choices(string.ascii_letters + string.digits, k=16))
        return v

    @field_validator("INDEXER_MANAGER_TYPE")
    def set_indexer_manager_type(cls, v, values):
        if v == "None":
            return None
        return v

    @field_validator("PROXY_DEBRID_STREAM_PASSWORD")
    def set_debrid_stream_proxy_password(cls, v, values):
        if v is None:
            return "".join(random.choices(string.ascii_letters + string.digits, k=16))
        return v


settings = AppSettings()


class ConfigModel(BaseModel):
    indexers: List[str] = Field(default_factory=list)
    indexersUncached: List[str] = Field(default_factory=list)
    languages: List[str] = Field(default=["All"])
    languagePreference: List[str] = Field(default_factory=list)
    searchLanguage: List[str] = Field(default_factory=list)
    resolutions: List[str] = Field(default=["All"])
    resultFormat: List[str] = Field(default=["All"])
    resolutionsOrder: List[str] = Field(default_factory=list)
    sortType: str = Field(default='Sort_by_Resolution_then_Rank')
    sortPreference: str = Field(default='Completion')
    scrapingPreference: str = Field(default='tz')
    maxResults: int = Field(default=0, ge=0)
    maxSize: float = Field(default=0, ge=0)
    debridService: str
    debridApiKey: str
    debridStreamProxyPassword: str = Field(default="")

    @field_validator("indexers", "indexersUncached")
    @classmethod
    def check_indexers(cls, v):
        settings.INDEXER_MANAGER_INDEXERS = [
            indexer.replace(" ", "_").lower()
            for indexer in settings.INDEXER_MANAGER_INDEXERS
        ]
        valid_indexers = [
            indexer for indexer in v if indexer in settings.INDEXER_MANAGER_INDEXERS
        ]
        return valid_indexers

    @field_validator("debridService")
    @classmethod
    def check_debrid_service(cls, v):
        valid_services = ["realdebrid", "alldebrid", "premiumize", "torbox", "debridlink"]
        if v not in valid_services:
            raise ValueError(f"Invalid debridService. Must be one of {valid_services}")
        return v


rtn_settings = SettingsModel()
rtn_settings.options["remove_ranks_under"] = -100000
rtn_ranking = BestRanking()

# For use anywhere
rtn = RTN(settings=rtn_settings, ranking_model=rtn_ranking)

database_url = (
    settings.DATABASE_PATH
    if settings.DATABASE_TYPE == "sqlite"
    else settings.DATABASE_URL
)
database = Database(
    f"{'sqlite' if settings.DATABASE_TYPE == 'sqlite' else 'postgresql+asyncpg'}://{'/' if settings.DATABASE_TYPE == 'sqlite' else ''}{database_url}"
)
