./args beefcafe `stat -c "%s" Release/debugger.bin` `crc32 Release/debugger.bin` `readelf -h Release/Debugger |grep Entry| sed 's/^.*0x//g'`

