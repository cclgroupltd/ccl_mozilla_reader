import pathlib
import re
import sys

import ccl_mozilla_reader

profile_path = pathlib.Path(sys.argv[1])
cache_path = pathlib.Path(sys.argv[2])

with ccl_mozilla_reader.MozillaProfileFolder(profile_path, cache_path) as profile:
    for x in profile.iterate_cache():
        print(x)

