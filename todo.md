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

### Still need to do:
- About FileResponse: Does not work in stremio app. Issue with headers/redirect. Works when range headers added. Issue when range headers added multiple calls of generate_download_link, fix is redirect to separate endpoint.
- Add uncached support for other debrid services as uncached logic is now general enough for it to be nearly copy pasted
- Add DEBRID_TAKE_FIRST support for the other services
- Check jackett/prowlarr missing infohashes sometimes, probably rate limits?