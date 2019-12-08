# tch-eck-search
Automatically find the ECK from a memory dump instead of relying on the user to specify it
Dumps all the eripv2 objects to disk when it finds the right ECK
Usually finds ECK within ~10 seconds. Worst case is ~24 hours.  It will try the faster methods first, then fall-back to an exhaustive search through all bytes in the mem dump
OCK key file is of relevance to decrypt encrypted rbi firmware files with another script 

Preparation:
From an ssh shell on your router, dump these two things to a USB flash disk:
1) Dump your eripv2 partition mtd5 for offline processing: dd if=/dev/mtd5 of=/mnt/usb_path/mtd5.dump  
2) Dump your memory for offline processing: dd if=/dev/mem of=/mnt/usb_path/mem.dump bs=1024

Copy both dump files to where you are able to run this python script 

Usage:
python3 tch-eck-search.py --eripv2 mtd5.dump --memdump mem.dump

