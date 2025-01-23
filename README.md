<h1 align="center" id="title">☄️ Comet - <a href="https://discord.gg/rivenmedia">Discord</a></h1>
<p align="center"><img src="https://socialify.git.ci/Zaarrg/comet-uncached/image?description=1&font=Inter&forks=1&language=1&name=1&owner=1&pattern=Solid&stargazers=1&theme=Dark" /></p>
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
- 🚀 **Advanced Binge Watching:** Advanced recognition of binge groups, allows for even single usenet files to be binged.
- 🎛️ **Customizable Results:** Customize how results are shown in Stremio (Result Order).
- 🔒 **Config Encryption:** Secure your configuration via the `TOKEN` environment variable.
- 🗂️ **Debrid Catalog:** View your recently uploaded files in Stremio as catalog
- 📰 **Usenet Support**: Supports usenet caching by using usenet indexer from prowlarr and torbox.
- ⬇️ **Auto Cache Next**: Automatically starts caching next episode.
- 🌐 **Improved URL Handling:**
    - Shortened URLs with filenames included.
    - Use the `TOKEN` environment variable for even shorter playback URLs, improving player compatibility.
    - Highly recommended even if encryption is not needed! As this improved player compatibility
- 📝 **Updates and Progress:** For detailed notes, see [todo.md](https://github.com/Zaarrg/comet-uncached/blob/main/todo.md).



## 🌟 **State of Uncached Support**

| Provider       | Status                               | Notes                                             | Supports Catalog       |
|----------------|--------------------------------------|---------------------------------------------------|------------------------|
| **Real Debrid** | ✅ Full Support                       | 🔄 *Seasons limit* + ✨ **DEBRID_TAKE_FIRST**      | ✅ *Allows catalog view*|
| **All Debrid**  | ✅ Full Support                       | 🔄 *Seasons limit* + ✨ **DEBRID_TAKE_FIRST**      | ✅ *Allows catalog view*|
| **Premiumize**  | ✅ Full Support                       | 🔄 *Seasons limit*                                | ❌                     |
| **Debrid Link** | ✅ Full Support                       | ✨ **DEBRID_TAKE_FIRST**                           | ✅ *Allows catalog view*|
| **Torbox**      | ✅ Full Support   + 📰 Usenet Support | 🔄 *Seasons limit* + ⬇️ *Auto Cache Next* + ✨ **DEBRID_TAKE_FIRST** + | ✅ *Allows catalog view*|

---

### Explanation of Symbols:

- ✅ **Full Support**: The provider supports uncached torrent functionality.
- ❌ **Unsupported**: The provider currently does not support uncached torrents.
- 🔄 **Seasons Limit**: For TV shows, torrents containing entire seasons must fully download before playback begins; individual episodes cannot be played as they complete. This is a technical limitation of the provider.
- ✨ **DEBRID_TAKE_FIRST**: Supports the environment variable to explicitly return the first e.g., 100 files from the provider, useful for private torrents uploaded via DebridMediaManager or the provider's UI.
- 🚧 **Work in Progress**: Feature planned but not yet available.
- ✅ **Supports Catalog**: Allows viewing and playing recently uploaded debrid files in Stremio under e.g. **Discover -> Others -> Comet RealDebrid**.
- 📰 **Usenet Support**: Supports usenet caching by using usenet indexer from prowlarr.
- ⬇️ **Auto Cache Next**: Supports auto caching next episode.
- ❌ **Does Not Support Catalog**: The provider does not have catalog integration in Stremio.


## 🚀 **Comet Uncached Run Down**

### 🔗 **Uncached for Torrentio:**
1. Add **torrentio** to the `INDEXER_MANAGER_INDEXERS` environment variable
2. Navigate to the **Configuration Page**.
3. Add **Torrentio** under the **Indexers Uncached** section.
4. 🎉 Done! Torrentio will now show uncached torrents.

### 📚 **For Other Indexers:**
1. Go to the **Configuration Page**.
2. Select under **Indexers** the indexers you want to enable.
3. Under **Indexers Uncached**, choose the indexers you want to be considered for uncached torrents.

### ⚙️ **Other Useful Options:**
- By default, all uncached torrents are grouped under the **Uncached Resolution** category.
- If you prefer uncached torrents to be sorted and treated like normal torrents:
    1. Deselect **Uncached** under the **Resolutions** section on the Configuration Page.
    2. This allows for sorting by resolution to function normally.

### 📰 **Usenet Support**:
- Only **Torbox** + **Prowlarr** Supports watching usenet files.
- This is in many aspects better then torrents as its not limited to **seeders** and **peers** meaning every file can be nearly always cached.
- Example usenet setup using **torbox** + **prowlarr**
  1. Add a usenet indexer to **Prowlarr** like **scenenzbs**
  2. Add the created **Indexer Name** to the **INDEXER_MANAGER_INDEXERS** environment variable
  3. Visit the Web Ui and select the added indexers under **Indexers** and **Indexers Uncached**
  4. Optionally adjust the **USENET_REFRESH_ATTEMPTS** env. By default this is 10 and seems to be more then enough for the **Torbox pro plan** download speed.
  5. 🎉 Done! Comet will now show the usenet results of **Prowlarr** and use **Torbox** to cache and stream.

> 💡 **Note:** This setup allows for even Uncached files to seem cached. Because the usenet files are not speed restricted by seeders or peers, it allows in combination 
> with Torbox Pro 80 Gbps download speed to add single Episodes with a size of e.g. 2 GB, which are then instantly downloaded. The USENET_REFRESH_ATTEMPTS parameter checks every 4 seconds—up 
> to USENET_REFRESH_ATTEMPTS times—whether the file is ready for streaming; if the file is ready before the last attempt, Stremio begins playback immediately.
> Meaning in Stremio only a longer loading screen is experienced then usual. This, in combination with the **Advanced Binge Watching** which allows for Single files to be binged watched 
> and not like usually with torrents which require the whole torrent to be one Season, guarantees a smooth watching experience. Of course this can as well fail if file names are inconsistent across episodes or the usenet file is broken and cant be repaired.

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

### 🗂️ **Supports Catalog:**
1. Navigate to **Discover -> Others -> Comet {Debrid Provider}** in Stremio to view and play recently uploaded files from your Debrid account.
2. Enjoy seamless access to your debrid uploads directly in Stremio. 🎉

💡 **Note:** If the catalog does not show up, try removing and re-adding the Comet addon in Stremio.

### 📋 **Sorting Order**
- Sorting follows a fixed hierarchical order:
    1. **Resolution**: Torrents are grouped and sorted by resolution.
    2. **Primary Sort**: Within each resolution, torrents are sorted by rank, seeders, or size based on the selected type.
    3. **Completion**: Complete torrents are prioritized within their resolution group while maintaining the primary sort order.
    4. **Cached Preference**: Cached torrents are moved to the top within their resolution if Uncached is deselected as Resolution, preserving their order.
    5. **Language Preference**: Torrents matching preferred languages are prioritized and moved to the top within their resolution group in the order specified in the configuration.


# 🚀 **Features**
- 🌐 **Proxy Debrid Streams**: The only Stremio addon that proxies Debrid streams, enabling multiple IPs to use the same account simultaneously!
- 🔄 **IP-Based Connection Limit**: Max connection limit and dashboard for Debrid stream proxying.
- 🧩 **Indexer Support**:
    - **Jackett** and **Prowlarr**: Set the `INDEXER_MANAGER_TYPE` environment variable to `jackett` or `prowlarr`.
    - **Zilean** ([DMM Scraper](https://hashlists.debridmediamanager.com/)): Unlock even more torrent results.
    - **Torrentio** ([Scraper](https://torrentio.strem.fun/)): Additional torrent sources.
- ⚡ **Smart Features**:
    - **Caching System**: Supports SQLite/PostgreSQL.
    - **Smart Torrent Ranking**: Powered by [RTN](https://github.com/dreulavelle/rank-torrent-name).
    - **Proxy Support**: Bypass Debrid restrictions effortlessly.
- 💾 **Debrid Services Supported**:
    - Real-Debrid, All-Debrid, Premiumize, TorBox, and Debrid-Link.
- 🎯 **Direct Torrent Support**: Activate direct torrents by not specifying a Debrid API Key (uses cached results from other users).
- 🎥 **Kitsu Integration**: Enjoy anime content with [Kitsu](https://kitsu.io/) support.
- 🔞 **Adult Content Filter**: Control content visibility with filtering options.



# 🛠️ **Installation**

To customize your Comet experience, review the available [environment variables](https://github.com/Zaarrg/comet-uncached/blob/main/.env-sample).

For a full docker example check the [docker-compose.yaml](https://github.com/Zaarrg/comet-uncached/blob/main/docker-compose.yaml) and [.stack-env](https://github.com/Zaarrg/comet-uncached/blob/main/.stack.env).

## 📦 **Self-Hosting**

### **From Source**
1. Clone the repository:
   ```sh
   git clone https://github.com/Zaarrg/comet-uncached
   cd comet-uncached
   ```
2. Install dependencies:
   ```sh
   pip install poetry
   poetry install
   ```
3. Start Comet:
   ```sh
   poetry run python -m comet.main
   ```

### **Using Docker**
1. Run the Docker image after modifying the environment variables:
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
    -e INDEXER_MANAGER_INDEXERS='["EXAMPLE1_CHANGETHIS", "EXAMPLE2_CHANGETHIS", "torrentio"]' \
    -e INDEXER_MANAGER_TIMEOUT=30 \
    -e TOKEN=XXXXXXXXXX \
    -e GET_TORRENT_TIMEOUT=5 \
    ghcr.io/zaarrg/comet-uncached:latest
   ```

2. To update your container:
    - Find the existing container:
      ```sh
      docker ps
      ```
    - Stop and remove it:
      ```sh
      docker stop <CONTAINER_ID>
      docker rm <CONTAINER_ID>
      ```
    - Pull the latest version:
      ```sh
      docker pull ghcr.io/zaarrg/comet-uncached:latest
      ```
    - Re-run the Docker command.

### **Using Docker Compose**
1. Copy the `docker-compose.yaml` file to a directory.
2. Copy `env-sample` to `.env` in the same directory.
3. Pull the latest version:
   ```sh
   docker compose pull
   ```
4. Start the container:
   ```sh
   docker compose up -d
   ```



## 🚧 **Debrid IP Blacklist**
To bypass Real-Debrid's (or AllDebrid's) IP blacklist, start a [Cloudflare-Warp container](https://github.com/cmj2002/warp-docker).



## 🎨 **Web UI Showcase**
![Comet Web UI](https://i.imgur.com/khJNQOo.png)
