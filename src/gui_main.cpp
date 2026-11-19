#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shobjidl.h>
#include <commctrl.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <shellapi.h>

#include <string>
#include <vector>
#include <thread>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cwctype>

#include "core.h"

using std::wstring;

static const wchar_t APP_TITLE[] = L"SSE4.2 Patcher";
static const wchar_t *BAKDIR = L"sse42-backup";

#define IDC_PATH 101
#define IDC_BROWSE 102
#define IDC_PATCH 103
#define IDC_RESTORE 104
#define IDC_LOG 105
#define IDC_NOUPD 106

#define WM_LOGLINE (WM_APP + 1)
#define WM_JOBDONE (WM_APP + 2)

static HWND hMain, hPath, hLog, hPatch, hRestore, hBrowse, hNoUpd;
static HFONT uiFont, monoFont;
static volatile bool busy;

static wstring w(const std::string &s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), NULL, 0);
    wstring r(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &r[0], n);
    return r;
}

static void out(const wstring& s) { PostMessageW(hMain, WM_LOGLINE, 0, (LPARAM)new wstring(s)); }

static wstring lc(wstring s) {
    for (size_t i = 0; i < s.size(); ++i) s[i] = (wchar_t)towlower(s[i]);
    return s;
}

static bool slurp(const wstring &p, std::vector<uint8_t> &buf)
{
    HANDLE f = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz; GetFileSizeEx(f, &sz);
    buf.resize((size_t)sz.QuadPart);
    size_t pos = 0; bool good = true;
    while (pos < buf.size()) {
        DWORD got = 0, want = (DWORD)std::min<size_t>(buf.size() - pos, 1u << 30);
        if (!ReadFile(f, &buf[pos], want, &got, 0) || !got) { good = false; break; }
        pos += got;
    }
    CloseHandle(f);
    return good;
}

static bool dump(const wstring& p, const std::vector<uint8_t>& d) {
    HANDLE f = CreateFileW(p.c_str(), GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE)
        return false;
    bool ok = true;
    for (size_t pos = 0; pos < d.size();) {
        DWORD put = 0, n = (DWORD)std::min<size_t>(d.size() - pos, 1u << 30);
        if (!WriteFile(f, d.data() + pos, n, &put, 0) || put == 0) { ok = false; break; }
        pos += put;
    }
    ok = FlushFileBuffers(f) && ok;
    CloseHandle(f);
    return ok;
}

static bool isFile(const wstring &p) { DWORD a = GetFileAttributesW(p.c_str()); return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY); }
static bool isDir(const wstring &p) { DWORD a = GetFileAttributesW(p.c_str()); return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY); }

static bool skipName(const wstring& name)
{
    static const wchar_t* pfx[] = { L"microsoft.", L"vcruntime", L"msvcp", L"ucrtbase", L"api-ms-",
        L"coremessagingxp", L"dxcompiler", L"d3dcompiler", L"sse42patch" };
    wstring n = lc(name);
    for (auto p : pfx) if (!n.compare(0, wcslen(p), p)) return true;
    return false;
}

static void walk(const wstring &dir, const wstring &rel, std::vector<wstring> &files, int depth)
{
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wstring nm = fd.cFileName;
        if (nm == L"." || nm == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (depth < 3 && lc(nm) != BAKDIR && lc(nm) != L"uninstall")
                walk(dir + L"\\" + nm, rel + nm + L"\\", files, depth+1);
        } else {
            wstring l = lc(nm);
            if (l.size() > 4) {
                wstring ext = l.substr(l.size() - 4);
                if ((ext == L".dll" || ext == L".exe") && !skipName(nm)) files.push_back(rel + nm);
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static bool mkparents(const wstring& file) {
    size_t s = file.rfind(L'\\');
    if (s == wstring::npos) return true;
    wstring d = file.substr(0, s);
    return SHCreateDirectoryExW(NULL, d.c_str(), NULL) == ERROR_SUCCESS || isDir(d);
}

static std::vector<wstring> procsIn(const wstring &folder)
{
    std::vector<wstring> found;
    wstring pre = lc(folder);
    if (!pre.empty() && pre[pre.size()-1] != L'\\') pre += L'\\';
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return found;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe)) {
        HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!ph) continue;
        wchar_t img[MAX_PATH*2]; DWORD n = MAX_PATH*2;
        if (QueryFullProcessImageNameW(ph, 0, img, &n) && lc(img).rfind(pre, 0) == 0) found.push_back(pe.szExeFile);
        CloseHandle(ph);
    }
    CloseHandle(snap);
    return found;
}

static void trimSlash(wstring &f) { while (!f.empty() && (f.back() == L'\\' || f.back() == L'/')) f.pop_back(); }

static void patchFolder(wstring folder, bool noUpdates)
{
    trimSlash(folder);
    out(L"Folder: " + folder);
    std::vector<wstring> running = procsIn(folder);
    if (running.size()) {
        out(L"ERROR: the browser is still running (" + running[0] + L"). Close it and try again.");
        return;
    }
    std::vector<wstring> list;
    walk(folder, L"", list, 0);
    bool hasXul = false;
    for (auto &f : list) if (lc(f) == L"xul.dll") hasXul = true;
    if (!hasXul) out(L"Warning: no xul.dll here, this does not look like a browser folder.");

    unsigned done = 0, already = 0, errs = 0, total = 0, skipped = 0;
    for (size_t i = 0; i < list.size(); i++) {
        const wstring &rel = list[i];
        wstring full = folder + L"\\" + rel;
        std::vector<uint8_t> src, dst;
        if (!slurp(full, src)) { out(L"  ! cannot read " + rel); errs++; continue; }
        sse42::Stats st;
        ULONGLONG t0 = GetTickCount64();
        auto res = sse42::PatchImage(src, dst, st, [](const std::string& m) { out(L"    " + w(m)); });
        if (res == sse42::Result::NothingToDo || res == sse42::Result::NotX64PE)
            continue;
        if (res == sse42::Result::AlreadyPatched) { already++; out(L"  = " + rel + L": already patched"); continue; }
        if (res == sse42::Result::Error) {
            errs++; out(L"  ! " + rel + L": failed, file left untouched");
            continue;
        }
        wstring bak = folder + L"\\" + BAKDIR + L"\\" + rel;
        if (!mkparents(bak) || !CopyFileW(full.c_str(), bak.c_str(), FALSE)) {
            out(L"  ! " + rel + L": could not create backup, skipping"); errs++;
            continue;
        }
        wstring tmp = full + L".sse42tmp";
        if (!dump(tmp, dst) || !MoveFileExW(tmp.c_str(), full.c_str(), MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(tmp.c_str());
            out(L"  ! " + rel + L": write failed (no permission? run as administrator)");
            errs++;
            continue;
        }
        done++; total += st.total(); skipped += st.skipped;
        wchar_t ln[512];
        swprintf(ln, 512, L"  + %ls: %u instructions (popcnt %u, crc32 %u, pcmpgtq %u, pcmpXstrX %u)%ls  [%llu ms]",
            rel.c_str(), st.total(), st.popcnt, st.crc32, st.pcmpgtq, st.pcmpstr,
            st.skipped ? L"  WARNING: some sites skipped!" : L"", (unsigned long long)(GetTickCount64() - t0));
        out(ln);
    }

    if (noUpdates) {
        wstring dist = folder + L"\\distribution";
        wstring pol = dist + L"\\policies.json";
        if (isFile(pol))
            out(L"policies.json already exists, add \"DisableAppUpdate\": true to it manually");
        else {
            CreateDirectoryW(dist.c_str(), NULL);
            const char *js = "{\n  \"policies\": {\n    \"DisableAppUpdate\": true\n  }\n}\n";
            out(dump(pol, std::vector<uint8_t>(js, js + strlen(js)))
                ? L"Automatic updates disabled (distribution\\policies.json)."
                : L"! could not write policies.json");
        }
    }

    wchar_t s[512];
    swprintf(s, 512, L"\nDone: patched %u files (%u instructions)%ls, already patched: %u, errors: %u.",
        done, total, skipped ? L", SOME SITES WERE SKIPPED" : L"", already, errs);
    out(s);
    if (done) out(L"Originals saved in: " + folder + L"\\" + BAKDIR + L"\nRun the patcher again after every browser update.");
}

static void restoreDir(const wstring &bdir, const wstring &folder, const wstring &rel, unsigned &n, unsigned &bad)
{
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((bdir + L"\\" + rel + L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wstring nm = fd.cFileName;
        if (nm == L"." || nm == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { restoreDir(bdir, folder, rel + nm + L"\\", n, bad); continue; }
        wstring from = bdir + L"\\" + rel + nm, to = folder + L"\\" + rel + nm;
        std::vector<uint8_t> cur; sse42::Stats tmp;
        if (slurp(to, cur) && sse42::ScanImage(cur, tmp, [](const std::string&){}) != sse42::Result::AlreadyPatched) {
            DeleteFileW(from.c_str());
            out(L"  - " + rel + nm + L": not patched (newer version?), stale backup removed");
            continue;
        }
        if (!CopyFileW(from.c_str(), to.c_str(), FALSE)) { bad++; out(L"  ! could not restore " + rel + nm); continue; }
        DeleteFileW(from.c_str()); n++;
        out(L"  < " + rel + nm);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    RemoveDirectoryW((bdir + L"\\" + rel).c_str());
}

static void restoreFolder(wstring folder)
{
    trimSlash(folder);
    std::vector<wstring> r = procsIn(folder);
    if (!r.empty()) { out(L"ERROR: the browser is still running (" + r[0] + L")."); return; }
    wstring bdir = folder + L"\\" + BAKDIR;
    if (!isDir(bdir)) { out(L"No backup found in " + bdir); return; }
    unsigned n = 0, bad = 0;
    restoreDir(bdir, folder, L"", n, bad);
    RemoveDirectoryW(bdir.c_str());
    wchar_t s[200];
    swprintf(s, 200, L"Restored %u files, errors: %u.", n, bad);
    out(s);
}

static void setBusy(bool b) {
    busy = b;
    EnableWindow(hPatch, !b); EnableWindow(hRestore, !b); EnableWindow(hBrowse, !b);
}

static void go(bool patch)
{
    if (busy) return;
    int len = GetWindowTextLengthW(hPath);
    wstring folder(len, 0);
    GetWindowTextW(hPath, &folder[0], len + 1);
    if (folder.empty() || !isDir(folder)) {
        MessageBoxW(hMain, L"Select the browser folder (the one containing xul.dll).", APP_TITLE, MB_ICONWARNING);
        return;
    }
    bool nu = SendMessageW(hNoUpd, BM_GETCHECK, 0, 0) == BST_CHECKED;
    setBusy(true);
    SetWindowTextW(hLog, L"");
    std::thread([folder, nu, patch]() {
        if (patch) patchFolder(folder, nu);
        else restoreFolder(folder);
        PostMessageW(hMain, WM_JOBDONE, 0, 0);
    }).detach();
}

static void pickFolder()
{
    IFileOpenDialog *dlg = NULL;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg)))) return;
    DWORD o; dlg->GetOptions(&o);
    dlg->SetOptions(o | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dlg->SetTitle(L"Select the browser folder (containing xul.dll)");
    IShellItem *it;
    if (SUCCEEDED(dlg->Show(hMain)) && SUCCEEDED(dlg->GetResult(&it))) {
        PWSTR p;
        if (SUCCEEDED(it->GetDisplayName(SIGDN_FILESYSPATH, &p))) { SetWindowTextW(hPath, p); CoTaskMemFree(p); }
        it->Release();
    }
    dlg->Release();
}

static wstring defaultFolder()
{
    const wchar_t *tries[] = { L"%ProgramFiles%\\Waterfox", L"%LOCALAPPDATA%\\Waterfox", L"%ProgramFiles%\\Waterfox Current" };
    wchar_t b[MAX_PATH];
    for (int i = 0; i < 3; i++) {
        ExpandEnvironmentStringsW(tries[i], b, MAX_PATH);
        if (isFile(wstring(b) + L"\\xul.dll")) return b;
    }
    GetModuleFileNameW(NULL, b, MAX_PATH);
    wstring me(b);
    me.erase(me.rfind(L'\\'));
    return isFile(me + L"\\xul.dll") ? me : L"";
}

static int dpi(int v) {
    static int d;
    if (!d) { HDC dc = GetDC(0); d = GetDeviceCaps(dc, LOGPIXELSX); ReleaseDC(0, dc); }
    return MulDiv(v, d, 96);
}

static void relayout(int cx, int cy)
{
    int m = dpi(10), bh = dpi(26), bw = dpi(110), wide = bw + dpi(40);
    MoveWindow(hPath, m, m, cx - 3*m - bw, bh, TRUE);
    MoveWindow(hBrowse, cx - m - bw, m, bw, bh, TRUE);
    int y = 2*m + bh;
    MoveWindow(hPatch, m, y, wide, bh + dpi(6), TRUE);
    MoveWindow(hRestore, 2*m + wide, y, wide, bh + dpi(6), TRUE);
    MoveWindow(hNoUpd, 3*m + 2*wide, y + dpi(4), cx - (4*m + 2*wide), bh, TRUE);
    y += bh + dpi(6) + m;
    MoveWindow(hLog, m, y, cx - 2*m, cy - y - m, TRUE);
}

static HWND ctl(HWND parent, const wchar_t *cls, const wchar_t *txt, DWORD st, int id, DWORD ex = 0)
{
    HWND c = CreateWindowExW(ex, cls, txt, WS_CHILD|WS_VISIBLE|st, 0, 0, 10, 10, parent, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)uiFont, TRUE);
    return c;
}

static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        hMain = h;
        NONCLIENTMETRICSW ncm; ncm.cbSize = sizeof(ncm);
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        uiFont = CreateFontIndirectW(&ncm.lfMessageFont);
        monoFont = CreateFontW(-dpi(13), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
        hPath = ctl(h, L"EDIT", defaultFolder().c_str(), ES_AUTOHSCROLL|WS_TABSTOP, IDC_PATH, WS_EX_CLIENTEDGE);
        SendMessageW(hPath, EM_SETCUEBANNER, TRUE, (LPARAM)L"Browser folder (e.g. C:\\Program Files\\Waterfox)");
        hBrowse = ctl(h, L"BUTTON", L"Browse...", BS_PUSHBUTTON|WS_TABSTOP, IDC_BROWSE);
        hPatch = ctl(h, L"BUTTON", L"Patch", BS_DEFPUSHBUTTON|WS_TABSTOP, IDC_PATCH);
        hRestore = ctl(h, L"BUTTON", L"Restore originals", BS_PUSHBUTTON|WS_TABSTOP, IDC_RESTORE);
        hNoUpd = ctl(h, L"BUTTON", L"Disable auto-updates", BS_AUTOCHECKBOX|WS_TABSTOP, IDC_NOUPD);
        hLog = ctl(h, L"EDIT", L"", ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|WS_HSCROLL, IDC_LOG, WS_EX_CLIENTEDGE);
        SendMessageW(hLog, WM_SETFONT, (WPARAM)monoFont, TRUE);
        SendMessageW(hLog, EM_SETLIMITTEXT, 0, 0);
        out(L"Replaces SSE4.2/POPCNT instructions (popcnt, crc32, pcmpgtq, pcmpXstrX) with emulation,\n"
            L"so browsers built for x86-64-v2 run on Core 2 / Xeon 5400 class CPUs (SSE4.1).\n"
            L"Pick the folder containing xul.dll and click \"Patch\". Originals go to sse42-backup.");
        return 0;
    }
    case WM_SIZE: relayout(LOWORD(lp), HIWORD(lp)); return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO*)lp)->ptMinTrackSize.x = dpi(600);
        ((MINMAXINFO*)lp)->ptMinTrackSize.y = dpi(300);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_BROWSE) pickFolder();
        else if (LOWORD(wp) == IDC_PATCH) go(true);
        else if (LOWORD(wp) == IDC_RESTORE) go(false);
        return 0;
    case WM_LOGLINE: {
        wstring *p = (wstring*)lp, t;
        for (size_t i = 0; i < p->size(); i++) {
            if ((*p)[i] == L'\n' && (i == 0 || (*p)[i-1] != L'\r')) t += L'\r';
            t += (*p)[i];
        }
        delete p;
        t += L"\r\n";
        int e = GetWindowTextLengthW(hLog);
        SendMessageW(hLog, EM_SETSEL, e, e);
        SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)t.c_str());
        return 0;
    }
    case WM_JOBDONE: setBusy(false); return 0;
    case WM_CLOSE:
        if (busy && MessageBoxW(h, L"Patching is still in progress. Close anyway?", APP_TITLE, MB_YESNO|MB_ICONWARNING) != IDYES) return 0;
        DestroyWindow(h);
        return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"SSE42PatchWnd";
    wc.hIcon = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
    wc.hIconSm = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    RegisterClassExW(&wc);

    HWND wnd = CreateWindowExW(0, wc.lpszClassName, APP_TITLE, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        dpi(820), dpi(520), NULL, NULL, inst, NULL);
    ShowWindow(wnd, show);
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0)
        if (!IsDialogMessageW(wnd, &m)) { TranslateMessage(&m); DispatchMessageW(&m); }
    CoUninitialize();
    return 0;
}
