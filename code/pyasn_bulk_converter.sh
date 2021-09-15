#!/bin/bash

source /home/nils/virt_env_BGPstream/bin/activate

#First fetch daily RIB dumps from 8 collectors
cd /data/
python /data/pyasn_downloader.py --exp9

#Delete dat file if bz2 file from same collector is present
#This is only done for all bz2 files meaning that if a bz2 download failed and it isn´t present then the old dat shouldn´t be removed.
FILES=*.bz2
IFS='_'
for f in $FILES
do
  echo "$f"
  read -ra ADDR <<< "$f" #split string, delimiter _
  rm "${ADDR[0]}"*".dat" #remove old dat file
  OUTPUT="${f%.*}.dat" #set new dat filename
  python /data/pyasn_converter.py --single "$f" "$OUTPUT" #run pyasn converter for this RIB
  rm "$f" #remove bz2
done
