<p align="center"><img src="https://i.imgur.com/mkpkD6K.png" /></p>
<h1 align="center" id="title">☄️ Comet - <a href="https://discord.gg/rivenmedia">Discord</a></h1>
<p align="center"><img src="https://socialify.git.ci/g0ldyy/comet/image?description=1&font=Inter&forks=1&language=1&name=1&owner=1&pattern=Solid&stargazers=1&theme=Dark" /></p>
<p align="center">
  <a href="https://ko-fi.com/E1E7ZVMAD">
    <img src="https://ko-fi.com/img/githubbutton_sm.svg">
  </a>
</p>

## ⚠️ **Fork Disclaimer**
- 🚧 **Work in Progress:** This is a fork of the official [Comet repository](https://github.com/g0ldyy/comet). It will be abandoned once all features are implemented in the original repo.
- ✨ **Primary Goal:** Add uncached support and enhance features.
- 🛠️ **Stay Updated:** Check the current progress and updates in the [todo.md](https://github.com/Zaarrg/comet-uncached/blob/main/todo.md).
- ⚠️ **Caution:** Stuff might break frequently as this is under active development!


## 🌟 **Fork Features**
- 🔍 **Advanced Language Search:** Search in multiple languages.
- 🔧 **Advanced Sorting and Preferences:** Sort by language, rank, seeders, size, or completion.
- 🎛️ **Customizable Results:** Customize how results are shown in Stremio (Result Order).
- 🔒 **Config Encryption:** Secure your configuration via the `TOKEN` environment variable.
- 🌐 **Improved URL Handling:**
    - Shortened URLs with filenames included.
    - Use the `TOKEN` environment variable for even shorter playback URLs, improving player compatibility.
    - Highly recommended even if encryption is not needed! As this improved player compatibility
- 📝 **Updates and Progress:** For detailed notes, see [todo.md](https://github.com/Zaarrg/comet-uncached/blob/main/todo.md).



## 🌟 **State of Uncached Support**

| Provider       | Status                                      | Notes                                           |
|----------------|---------------------------------------------|------------------------------------------------|
| **Real Debrid** | ✅ Full Support                            | 🔄 *Seasons limit* + ✨ **DEBRID_TAKE_FIRST**   |
| **All Debrid**  | ✅ Full Support                            | 🔄 *Seasons limit* + ✨ **DEBRID_TAKE_FIRST**   |
| **Premiumize**  | ✅ Full Support                            | 🔄 *Seasons limit*                             |
| **Debrid Link** | ✅ Full Support                            | ✨ **DEBRID_TAKE_FIRST**                        |
| **Torbox**      | ❌ Unsupported                            | 🚧 *Will be added once sign-ups open*          |



### Explanation of Symbols:

- ✅ **Full Support**: The provider supports uncached torrent functionality.
- ❌ **Unsupported**: The provider currently does not support uncached torrents.
- 🔄 **Seasons Limit**: For TV shows, torrents containing entire seasons must fully download before playback begins; individual episodes cannot be played as they complete. This is a technical limitation of the provider.
- ✨ **DEBRID_TAKE_FIRST**: Supports the environment variable to explicitly return the first e.g. 100 files from the provider, useful for private torrents uploaded via DebridMediaManager or the provider's UI.
- 🚧 **Work in Progress**: Feature planned but not yet available.


## 🚀 **Comet Uncached Run Down**

### 🔗 **Uncached for Torrentio:**
1. Navigate to the **Configuration Page**.
2. Add **Torrentio** under the **Indexers Uncached** section.
3. 🎉 Done! Torrentio will now support uncached torrents.

### 📚 **For Other Indexers:**
1. Go to the **Configuration Page**.
2. Select the indexers you want to enable.
3. Under **Indexers Uncached**, choose the indexers you want to be considered for uncached torrents.

### ⚙️ **Other Useful Options:**
- By default, all uncached torrents are grouped under the **Uncached Resolution** category.
- If you prefer uncached torrents to be sorted and treated like normal torrents:
    1. Deselect **Uncached** under the **Resolutions** section on the Configuration Page.
    2. This allows for sorting by resolution to function normally.

### 🌍 **Language Support**
- **Default Behavior:** Comet compares torrent titles to all languages by default.
- **Language Preference:**
    - To sort specific languages to the top, select them under **Language Preference**.
- **Prowlarr/Jackett/Zilean:**
    - To search these in additional languages, enable **Language Search** for your desired languages.
    - ⚠️ *Note:* Selecting many languages may significantly increase search time.

### 📋 **Result Order**
- This determines the order in which results are displayed.
- To customize:
    1. Deselect all options.
    2. Select the options in the order you prefer.


# Features
- The only Stremio addon that can Proxy Debrid Streams to allow use of the Debrid Service on multiple IPs at the same time on the same account!
- IP-Based Max Connection Limit and Dashboard for Debrid Stream Proxier
- Jackett and Prowlarr support (change the `INDEXER_MANAGER_TYPE` environment variable to `jackett` or `prowlarr`)
- [Zilean](https://github.com/iPromKnight/zilean) ([DMM](https://hashlists.debridmediamanager.com/) Scraper) support for even more results
- [Torrentio](https://torrentio.strem.fun/) Scraper
- Caching system ft. SQLite / PostgreSQL
- Smart Torrent Ranking powered by [RTN](https://github.com/dreulavelle/rank-torrent-name)
- Proxy support to bypass debrid restrictions
- Real-Debrid, All-Debrid, Premiumize, TorBox and Debrid-Link supported
- Direct Torrent supported (do not specify a Debrid API Key on the configuration page (webui) to activate it - it will use the cached results of other users using debrid service)
- [Kitsu](https://kitsu.io/) support (anime)
- Adult Content Filter

# Installation
To customize your Comet experience to suit your needs, please first take a look at all the [environment variables](https://github.com/g0ldyy/comet/blob/main/.env-sample)!

## Self Hosted
### From source
- Clone the repository and enter the folder
    ```sh
    git clone https://github.com/Zaarrg/comet-uncached
    cd comet
    ```
- Install dependencies
    ```sh
    pip install poetry
    poetry install
    ````
- Start Comet
    ```sh
    poetry run python -m comet.main
    ````

### With Docker
- Simply run the Docker image after modifying the environment variables
  ```sh
  docker run --name comet -p 8000:8000 -d \
      -e FASTAPI_HOST=0.0.0.0 \
      -e FASTAPI_PORT=8000 \
      -e FASTAPI_WORKERS=1 \
      -e CACHE_TTL=86400 \
      -e DEBRID_PROXY_URL=http://127.0.0.1:1080 \
      -e INDEXER_MANAGER_TYPE=jackett \
      -e INDEXER_MANAGER_URL=http://127.0.0.1:9117 \
      -e INDEXER_MANAGER_API_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
      -e INDEXER_MANAGER_INDEXERS='["EXAMPLE1_CHANGETHIS", "EXAMPLE2_CHANGETHIS"]' \
      -e INDEXER_MANAGER_TIMEOUT=30 \
      -e TOKEN=XXXXXXXXXX \
      -e GET_TORRENT_TIMEOUT=5 \
      ghcr.io/zaarrg/comet-uncached:latest
  ```
    - To update your container

        - Find your existing container name
      ```sh
      docker ps
      ```

        - Stop your existing container
      ```sh
      docker stop <CONTAINER_ID>
      ```

        - Remove your existing container
      ```sh
      docker rm <CONTAINER_ID>
      ```

        - Pull the latest version from docker hub
      ```sh
      docker pull g0ldyy/comet
      ```

    - Finally, re-run the docker run command
 
### With Docker Compose
- Copy *docker-compose.yaml* in a directory
- Copy *env-sample* to *.env* in the same directory
- Pull the latest version from docker hub
    ```sh
      docker compose pull
    ```
- Run
    ```sh
      docker compose up -d
    ```

## Debrid IP Blacklist
To bypass Real-Debrid's (or AllDebrid) IP blacklist, start a cloudflare-warp container: https://github.com/cmj2002/warp-docker

## Web UI Showcase
<img src="https://i.imgur.com/khJNQOo.png" />
