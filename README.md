 secr   
################################################################ 
 surrealiz3   
################################################################ 
  
  grab your ECK key with r2secr.arm.ko ( insmod r2secr.arm.ko && dmesg )  
  or with r2secr.mips.ko ( insmod r2secr.mips.ko && dmesg  )   
 
 output 

 34399.350000] r2secr : 1ffdf000   
 [34399.352000] r2secr_struct : dffdf000   
 [34399.356000] r2secr_struct->magic : d104ea5b   
 [34399.361000] r2secr_struct->items : dffdf008   
 [34399.365000] nextFreeItem->id : 11f   
 [34399.369000] nextFreeItem->length : 16   
 [34399.372000] nextFreeItem->data : 1ffdf020   
 [34399.377000] data_ptr : dffdf020   
 [34399.380000] XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  |  ................   

 grab you eripv2 partition ,mtd5 for offline processing dd if=/dev/mtd5 of=/tmp/mtd5.dd   
 copy it to where you are able to run this python script 

 run: python eripv2.py --eripv2 mtd5.dd --eckey XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

 find the secrets on screen and dumped unencrypted contents to files ( messy :P )  
 OCK key file is of relevance to decrypt encrypted rbi files with another script 
 disclaimer : use at your own risk 

 relevant : 

 OSCK 
 OSIK 
 EIK 

 ** lime.arm.ko to dump memory , so :  
 
 insmod lime.arm.ko "path="/tmp/run/mountd/sda1" format=raw"

** ripdrv.arm.ko 

remove original ripdrv.ko   

rmmod keymanager  
rmmod ripdrv.ko   
insmod ripdrv.arm.ko   

all private cryptos exposed now on /proc/rip   
efu stuff on /proc/efu   













