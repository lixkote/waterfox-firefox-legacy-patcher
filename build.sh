#!/bin/bash
set -e
cd "$(dirname "$0")"
runtime/build_blob.sh >/dev/null 2>&1
mkdir -p obj dist
[ -f obj/zydis_win.o ] || x86_64-w64-mingw32-gcc -O2 -c -Ithird_party third_party/Zydis.c -o obj/zydis_win.o
[ -f obj/zydis_linux.o ] || gcc -O2 -c -Ithird_party third_party/Zydis.c -o obj/zydis_linux.o
CXXW="x86_64-w64-mingw32-g++ -O2 -std=c++17 -Ithird_party -Isrc -static -s"
x86_64-w64-mingw32-windres -I res res/app.rc -O coff -o obj/app_res.o
$CXXW -municode -mwindows src/gui_main.cpp src/core.cpp obj/zydis_win.o obj/app_res.o -o dist/sse42patch.exe -lole32 -lshell32 -lcomctl32 -luuid
$CXXW src/core.cpp src/cli_main.cpp obj/zydis_win.o -o dist/sse42patch-cli.exe
g++ -O2 -std=c++17 -Ithird_party -Isrc src/core.cpp src/cli_main.cpp obj/zydis_linux.o -o sse42patch_cli
ls -la dist
