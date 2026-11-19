# waterfox-no-sse-4.2-popcnt
<p align="left">
    <img src="https://raw.githubusercontent.com/lixkote/waterfox-no-sse-4.2-popcnt/refs/heads/main/trollcat.png">
</p>
Patches waterfox binaries in a folder to patch and remove SSE 4.2 requirement (waterfox on core 2 duo, yay)
Needs SSE4.1 tho

Close the browser, run sse42patch.exe, pick the folder with your browser files, hit patch
Originals are kept in sse42-backup, "Restore originals" puts them back
Browser updates replace the patched files, so re-run it after updating

popcnt / crc32 / pcmpgtq / pcmpestri / pcmpestrm / pcmpistri / pcmpistrm get redirected
to trampolines in a new .sse42em section popcnt and pcmpgtq are done inline, the rest
goes through a small emulator (runtime/)