./args beefcafe `stat -f "%z" debugger.bin` `/Users/simon_hall/riscv-linux32/bin/riscv32-unknown-linux-gnu-readelf -h debugger.elf |grep Entry| sed 's/^.*0x//g'` `crc32 debugger.bin`
