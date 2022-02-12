./args beefcafe `stat -c "%s" Release/debugger.bin` `readelf -h Release/Debugger |grep Entry| sed 's/^.*0x//g'` `crc32 Release/debugger.bin`

