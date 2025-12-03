#!/bin/sh

DIR="/srv/share"

inotifywait -m -r -e close_write,create "$DIR" |
while read path action file; do
    logger -t watch-share "Detected $action on $path$file"
    # run your command here, e.g.:
    rclone copy $DIR sharepoint:/General
done
