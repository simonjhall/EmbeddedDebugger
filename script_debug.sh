./args beefcafe `stat -c "%s" Debug/debugger.bin` `readelf -h Debug/Debugger |grep Entry| sed 's/^.*0x//g'` `crc32 Debug/debugger.bin`

