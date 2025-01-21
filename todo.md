### Update 1.0
- Added Sorting of Results by Resolution + WebUi
- Added a Max Uncached Option to limit those results + WebUi
- Added a WebUi for which indexers to consider for uncached results
- Added Validation for selected uncached indexers
- Added Uncached Warning to title (Only for the selected indexers)
- Modified Real Debrid to handle uncached files
	- Added DB Table to cache uncached files + cleanup

### Update 2.0
- If max uncached specified keeps only the ones with most seeders
- Option to show Seeders in the title (Seeders are always shown for uncached results)
- Refactored logic to add uncached files into a more general function
- Added Sorting, ["Sort_by_Rank" (Default), "Sort_by_Resolution", "Sort_by_Resolution_then_Seeders", "Sort_by_Resolution_then_Size"]
- Added language Preferences

### Update 3.0
- Generalized getting uncached torrents
- Optimized sorting of torrents
- Optimized add_uncached_files to be only one loop
- Removed unnecessary max_uncached value, as max_results already does that
- Uncached torrents with magnet will use that instead of always downloading the file
- Early return for uncached results to prevent unnecessary debrid api calls
- Warning if debrid selecting files fails because of invalid video format
- Changed Uncached torrents index logic as it was completely wrong
- Added User Option to toggle torrentio and zilean search, useful if server supports those but only wants a select few indexers
- Added Option for additional Search Languages. Gets the available titles from imdb.
- Added Custom (Enhanced) Language Matching option. Rtn does not really return all languages in a title causing the language preference to be useless, this trys to enhance that.
- Adjusted Title Matching Filter to make sure the title name does not have multiple titles causing a false result
- Added ability to customize the order of Title Format, Result Order and Language Preference in web ui depending on what is selected first
- Replaced FileResponse with custom redirect to custom assets endpoint. Allows for range headers for stremio app and for redirect away from playback endpoint preventing necessary function calls

### Update 4.0
- Full generalization/modularization as far as possible and practical of uncached logic (refactor)
- Debrid Link uncached support
- File extensions added to url. Only when possible. Primarily only for cached results. Does not work for uncached torrents for example.
- Added DEBRID_TAKE_FIRST env. Explicitly returns first results on debrid profile. Useful for private uploads or if indexers are down on jackett/prowlarr. Atm only for debrid-link and real-debrid.

### Update 4.1
- Added UNCACHED_TTL. Needed to make sure uncached-cache-db gets fully cleared. 
  - Time when uncached torrents which download was started but never watched or finished will be deleted
  - Depends on CACHED_TTL. Meaning numbers smaller then that dont really make sense.
  - Basically the time a torrent has to be cached/downloaded until forgotten.

###  Update 5
- Added TOKEN env. Uses AES-256 with CTR mode and zlib compression to encrypt/decrypt the config in the url
  - Uses a post request on /configure to encode/decode
- Fixed missing URL_PREFIX and file_extension when loading cached results
- Removed no:norwegian for enhanced language check to improve anime compatibility
- Fixed Sort by seeders not working when titles had no seeders info
- Added seeders for torrentio
- Fixed configure ui using a order able select for Result Format

### Small Changes between 5 - 5.1
- Removed enhancedLanguageMatching as was not required anymore after merge
- Postgres support and index selection fix for uncached torrents
- Fix uncached add function missing some trackers when comparing
- Refactored ConfigModel
- Bunch of other small fixes not worth mentioning

### Update 5.1
- Adjusted sorting, now sorts available ```"Sort_by_Resolution_then_Rank", "Sort_by_Resolution_then_Seeders", "Sort_by_Resolution_then_Size"```
- Added behaviorHints to stream metadata like bingeGroup and filename. Allows skip/next button on tv shows to work and some better compatibility with players

### Update 5.2
- Fixed language search using language codes to check country codes
  - Now uses country codes and language codes to find the correct title
- Fixed langauge search not removing dupes because of case insensitivity

### Update 5.3
- Added sortPreference option for later on sorting by for example codec and more
- Added to sortPreference Completion Sorting and to Result Format
  - Allows for sorting torrents that have the whole season to the top
  - Also shows this in the Result Format Title if enabled
- Added uncached property to other debrid services
- Added complete key to files returned for tv shows from debrid services to allow for completion sorting
- Added check_completion function to check if a torrent is the whole season (complete: true)
- Added tiebreaker for sort by resolution to be size property (seeders prop is not always present)
- Adjusted format title as in some cases to many newlines where present and stremio would cut infos

### Update 5.4
- Added error catch for real debrid disabled endpoint
- Improved Season Completion detection
- Fixed index selection for uncached results.
- Added Torrentio uncached support.
  - Just add torrentio to the env INDEXER_MANAGER_INDEXERS=["Torrentio"] and then select torrentio in the settings under uncached indexers.
  
### Update 5.5
- Fix of IndexError while using title match check + Zilean. See [issue](https://github.com/Zaarrg/comet-uncached/issues/4)
- Fix invalid file index detection for uncached movies
- Fixed download link cache being broken by latest file index fix
- Added comment explaining function of uncached index
- Small fix for debrid link to work with torrentio. Debrid link still experimental only recommended for testing atm.

### Update 6
- BREAKING: Make sure to wipe your sqlite or postgres comet DB
- BREAKING: Make sure to re add your addon as the encrypted config changed and old encrypted urls wont work u will get invalid config
  - Improved encrypted config. Its even shorter now.
  - Removed unnecessary b64 encoding causing the encrypted string to be base64 encoded twice.
  - Shortened playback url even more if TOKEN env is provided
- Full Uncached Torrents database refactor
- Full Debrid Link Support + DEBRID_TAKE_FIRST
- All missing uncached features implemented
- Fixed issue with multiple uncached Streams not playing.
  - Its now possible to start Caching a batch of episodes and then play E01 as soon as ready without having to wait for the whole container/season to be cached.
  - This depends on provider, real debrid does not support this but debrid link does.
- Fixed multiple comet addons interfering with another for uncached results.
- Major improvement in multi download management using container and torrent ids for uncached torrents.
- Major uncached file selection improvement. Whole system reworked. Now nearly always right file will be selected.
- Fixed FileResponse finally... (Video length was to short and stremio was buggin out + behaviourHints)
- Added Cache Cleanup Background task. Prevents infinite growing of db. In a normal use case db size should normalize at most watch tv shows / movies
  - This will allow for entries to be deleted that where only cached for one person. E.g. Niche shows/movies.
- Added File names to urls
  - Uncached files names might be missing the file extension as it is unknown until the file is cached
- Multidownload of uncached is no longer possible there should be fixed
  - Potentially fixed [issue](https://github.com/Zaarrg/comet-uncached/issues/2) multiple downloads

### Update 6.1
- Merged Changes
- Simplified Cache
- Changed Uncached Cache to use same cache as normal torrents
  - Adjusted Cache to support it
  - Removed uncached_torrents db
- Uncached torrents status is now updated instantly
- Added completion check to title match check (Slightly better results)
- Added / Improved Aliases
  - Now by default returns results in all languages
  - Language Search now only needed specifically for the search in e.g. jackett
- Added prioritize Cached, sorts Cached results to the top if Uncached indexers but no Uncached resolution
- Changed json to orjson

### Update 6.2
- Language sorting fixed
  - Used full lang name instead of code
- Refactored some sorting functions

### Update 6.3
- Added All Debrid uncached Support + DEBRID_TAKE_FIRST
- Added Premiumize uncached Support
- Switched Uncached cache to use a derived debrid key as identifier
  - Fixes issue with premiumize and other debrid providers to only showing progress for own files
  - Uses irreversible derived key to prevent the real api key being saved into the db
- Some additional small fixes
- Added help-text for Completion sort
- Updated readme to fit better
- Adjusted uncached status update, to update for all users if one user finished caching
  - If for example 3 users are caching one file and users 1 finishes first it will update the cache status for everyone allowing the other to instantly watch as well

### Update 6.4
- Improved title match check, some better results for anime
  - Cleans parsed title of RTN as it sometimes had alternative titles
- Added Debrid Catalog
  - Added Debrid Catalog under Stremio - Discover - Others - Comet RealDebrid for example
  - Added get imdb id by title - Used to get imdb id to fill meta data for catalog
  - Catalog Supported by everything that supports DEBRID_TAKE_FRIST aswell
- Fixed sorting not working if Uncached selected under Resolution
  - [Releated Issue solved](https://github.com/Zaarrg/comet-uncached/issues/9)
- Updated rest of readme
- Removed torrentio from normal indexers as it is only needed under Indexers Uncached (WebUI visual)
- Fixed Premiumize wrong api endpoint

### Update 6.5
- Added and improved extras removal like samples, ncop, nced, making of
  - Added extras removal / skip to uncached file selection
  - Improved extras removal / skip for cached
  - Fixes e.g. anime openings being selected as episode
- Added Season check to uncached file selection

---
### List of new envs
- DEBRID_TAKE_FIRST - Returns this amount of results straight from debrid then runs through title match check
- URL_PREFIX - Prefix to use for all endpoints like "/comet"
- TOKEN - Token to use for encryption/decryption of config in url
- CACHE_WIPE - Time interval of whole Cache Cleanup trigger
- CACHE_WIPE_TTL - Time after when all entries in the cache will be deleted

### Sorting Order
- The sorting does have a fixed order
- If Sort_by_Resolution_then_Rank and SortPreference Completion and a Language Preference selected then:
- Sort_by_Resolution_then_Rank then Completion torrents to the top, then those sorted by rank/seeders or size depending on initial sort then language preference to the top in order of selection in configuration
- If Uncached is deselected in Resolution then before the language preference it will sort cached torrents to the top
- All the second and tertiary sorting happens inside the resolution itself

### State of Uncached Support
- Real Debrid: Full Support (Seasons limit) + DEBRID_TAKE_FIRST
- All Debrid: Full Support (Seasons limit) + DEBRID_TAKE_FIRST
- Premiumize: Full Support (Seasons limit)
- Debrid Link: Full Support + DEBRID_TAKE_FIRST

#### About Season limit
- For tv shows limited to only cache whole seasons / torrents.
- This means when caching a torrent with a whole season.
- And Episode 1 is fully downloaded, it wont be played until the whole season / video files of the torrent are downloaded.
- In contrast to for example Debrid Link, where as soon as episode 1 is downloaded it is playable, even if the whole season / torrent isn't downloaded
- This is a technical limit of the debrid provider and not fixable.

### Cache Timer Explained
- CACHE_TTL: Optional[int] = 86400 - Stremio Episode/Movie Cache. After 24h the results shown in streamio will be refreshed
- CACHE_WIPE: Optional[int] = 172800 - Interval in which the background cache clean up runs. (48h)
- CACHE_WIPE_TTL: Optional[int] = 86400 - TTL for the background cache clean task. Does the same as CACHE_TTL but specific to the task
- Set CACHE_WIPE = 0 to disable background cache clean up

### Still need to do:
- Maybe Add torbox usenet availability check (Not really needed and will add overhead but for better user experince)
- Maybe add Easynews+ as provider as well.
- Check jackett/prowlarr missing infohashes sometimes, probably rate limits?
  - Issue 5 might be related
- Add Language Tags to prowlarr and jackett search
  - Probably add new Language Tag option
- Fix Premiumize file upload. Does not allow any file upload for some reason.
  - Premiumize magnet fetching slow, maybe fixable.
- Maybe add separate sorting for uncached links.
- Improve status update. Atm with debrid take first takes two steps until it is shown as cached.

