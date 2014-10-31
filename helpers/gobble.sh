#!/bin/sh
inotifywait -m files_to_gobble -e create |
    while read path action file; do
        ../mtgx2MISP.py files_to_gobble/$file
        mv files_to_gobble/$file gobbled_files/
    done