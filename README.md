# Retron 5 Toolkit

This is a toolkit intended to help players root their Retron 5 console to get more features out of it, it appears that Hyperkin has stopped releasing updates for it.

The Retron 5 has a rk3066 SoC and uses the Rockchip image format for updates; these updates can be modified and repackaged using imgRePackerRK.

##### Requirements:
* Python 3
* Pycryptodomex >= 3.7.2

##### An example to enable ADB (build.prop inside system.img):
```
persist.service.adb.enable=1                                                    
persist.service.debuggable=1
persist.sys.usb.config=adb
```
##### Usage:
```
usage: Retron5.py [-h] [-i IN_FILE] [-o OUT_DIR] [-l] [-e] [-d]

A script to make unpacking and packing Retron 5 updates easier (or actually
possible)

optional arguments:
  -h, --help            show this help message and exit
  -i IN_FILE, --in-file IN_FILE
                        The update file you want to unpack
  -o OUT_DIR, --out-dir OUT_DIR
                        The directory you want to extract the update to
  -l, --list            List files in the update package
  -e, --extract         Extract files from the update package
  -d, --debug           Print debug info
```