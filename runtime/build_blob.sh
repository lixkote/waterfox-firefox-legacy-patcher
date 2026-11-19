#!/bin/bash
set -e
cd "$(dirname "$0")"
CF="-O2 -march=core2 -mtune=generic -ffreestanding -fno-builtin -fPIE -fno-plt -fvisibility=hidden -mno-red-zone -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fcf-protection=none -fno-jump-tables -Wall"
gcc $CF -c emu.c -o emu.o
gcc -c stub.S -o stub.o
for base in 0 0x10000; do
  ld -nostdlib -static --no-dynamic-linker -T link.ld --defsym BASE=$base -o blob_$base.elf stub.o emu.o
  objcopy -O binary -j .blob blob_$base.elf blob_$base.bin
done
cmp blob_0.bin blob_0x10000.bin && echo "blob is position independent"
readelf -r emu.o stub.o | grep -E "R_X86_64_(64|32S?) " && { echo "ABSOLUTE RELOCS!"; exit 1; } || true
cp blob_0.bin blob.bin
python3 -c "import sys;d=open('blob.bin','rb').read();print('static const unsigned char g_blob[] = {'+','.join(str(b) for b in d)+'};')" > ../src/blob.h
ls -la blob.bin
