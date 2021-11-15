
secr 

################################################################ 

disclaimer : use at your own risk 

** How to dump device keys and secrets

1. Get a USB stick and copy all the .ko files to it

2. Connect a USB drive to the router and config that it is mounted correctly i.e. 
```
root@mygateway:~# ls -la /mnt/usb/USB-*/*.ko
-rwxrwxrwx    1 root     root         ?0638 Dec 23  2018 /mnt/usb/USB-A1/lime.???.ko
-rwxrwxrwx    1 root     root          ?531 Dec 23  2018 /mnt/usb/USB-A1/r2secr.???.ko
-rwxrwxrwx    1 root     root         ?7183 Dec 23  2018 /mnt/usb/USB-A1/ripdrv.???.ko
root@mygateway:~#
```

3. Change current directory to USB mountpoint:
```
cd /mnt/usb/USB-A1/
```

4. Check your kernel version:
```
uname -a
```

5. Try grabbing your ECKey using r2secr:

On ARM (e.g. linux 4.1.38):
```
insmod r2secr.arm.4.1.38.ko && dmesg | tail -n 20 && rmmod r2secr
```

On ARM (if linux 3.4.11-rt19):
```
insmod r2secr.arm.3.4.11-rt19.ko && dmesg | tail -n 20 && rmmod r2secr
```

On MIPS (if linux 3.4.11-rt19): 
```
insmod r2secr.mips.3.4-rt19.ko && dmesg | tail -n 20 && rmmod r2secr
```

On MIPS (if linux 2.6): 
```
insmod r2secr.mips.2.6.ko && dmesg | tail -n 20 && rmmod r2secr
```

Same for other versions available in this repo. If you can't find a valid module for your platform, please, compile it and share it here ;-)

If it worked you will get output like:
```
root@mygateway:/tmp/run/mountd/sda1# insmod r2secr.mips.3.4.ko && dmesg | tail -n 10 && rmmod r2secr
[ 2554.482000] module cleanup
[ 2574.716000] r2secr : affdf800
[ 2574.719000] r2secr_struct : affdf800
[ 2574.726000] r2secr_struct->magic : d104ea5b
[ 2574.731000] r2secr_struct->items : affdf808
[ 2574.735000] nextFreeItem->id : 11f
[ 2574.738000] nextFreeItem->length : 16
[ 2574.742000] nextFreeItem->data : affdf820
[ 2574.747000] data_ptr : affdf820
[ 2574.750000] XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  |  ................
root@mygateway:/tmp/run/mountd/sda1#
```

If it didn't you need to grab a full RAM dump with LiME and take the ECKey from it.
Read further in this page about how to to it.

6. Grab your eripv2 partition (mtd5 normally, confirm with 'cat /proc/mtd') for offline processing (should go to USB stick if steps have been followed)
```
cd /mnt/usb/USB-A1/
dd if=/dev/mtd5 of=mtd5.dump
```

7. Copy it to a computer where you are able to run this python script with the key from above (with quotes if you keep spaces)
```
python3 eripv2.py --eripv2 mtd5.dump --eckey "XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX"
```

The secrets will be displayed on screen and dumped unencrypted contents to files ( messy :P )  
OSCK key file is of relevance to decrypt encrypted rbi files with another script
Relevant : 
OSCK
OSIK
EIK

** How to decrypt RBI firmwares

1. Copy RIP_ID_OSCK_0x0121-... to BOARD_NAME.osck

2. Use blidec_enhanced.py with .osck file from last step and .rbi firmware to decrypt to .bin
```
python3 blidec_enhanced.py --osck BOARD_NAME.osck --rbi my_firmware.rbi
```

3. Inspect .bin root file system using 7-Zip or binwalk

** How to dump memory on newer platforms with LiME
On some newer firmwares /dev/mem is not exposed or r2secr kernel symbol is not exported. You need to search for your ECKey into the full RAM dump made with LiME

On ARM (if Linux 3.4.11-rt19):
```
# Double check the "path=..." exists before running this command
insmod lime.arm.3.4.11-rt19.ko "path="/tmp/run/mountd/sda1" format=raw"
```

[Read more about LiME usage on 504ensicsLabs/LiME.](https://github.com/504ensicsLabs/LiME)


** How to expose all rip values in /proc
```
rmmod keymanager
rmmod ripdrv
insmod ripdrv.arm.3.4.ko
```

All private cryptos exposed now at /proc/rip   
EFU stuff at /proc/efu
