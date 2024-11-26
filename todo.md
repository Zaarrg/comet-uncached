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
  
---
### List of new envs
- UNCACHED_TTL - Time when uncached results that started downloading and never finished or where never watched will be deleted out of cache
- DEBRID_TAKE_FIRST - Returns this amount of results straight from debrid then runs through title match check
- URL_PREFIX - Prefix to use for all endpoints like "/comet"
- TOKEN - Token to use for encryption/decryption of config in url

### Sorting Order
- The sorting does have a fixed order
- If Sort_by_Resolution_then_Rank and SortPreference Completion and a Language Preference selected then:
- Sort_by_Resolution_then_Rank then Completion torrents to the top, then those sorted by rank/seeders or size depending on initial sort then language preference to the top in order of selection in configuration
- All the second and tertiary sorting happens inside the resolution itself

### Still need to do:
- About FileResponse: Does not work in stremio app. Issue with headers/redirect. Works when range headers added. Issue when range headers added multiple calls of generate_download_link, fix is redirect to separate endpoint.
- Add uncached support for other debrid services as uncached logic is now general enough for it to be nearly copy pasted
- Add DEBRID_TAKE_FIRST support for the other services
- Check jackett/prowlarr missing infohashes sometimes, probably rate limits?

