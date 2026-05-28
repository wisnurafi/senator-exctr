// ============================================================================
// Senator Loader DLL
//
// Lives inside RobloxPlayerBeta.exe after the external Senator.dll injects it
// via LoadLibraryW. Phase 1: heartbeat only — proves the loader runs in-process
// and we can talk to a console allocated by the external side.
//
// Phase 2 (planned): resolve Roblox's Lua API (lua_pcall / luau_load) and run
// the compiled init script directly. No more spoof, no more keystroke spam.
//
// Two entry paths are supported:
//   * DllMain (DLL_PROCESS_ATTACH) — used when the loader is loaded via
//     LoadLibraryW. The OS runs _DllMainCRTStartup before reaching us.
//   * ProveLife (exported, kernel32-only, no CRT dependencies) — used when
//     the loader is manually mapped. Manually-mapped DLLs cannot safely run
//     the CRT entry, so this is the proof-of-life path for that mode.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

namespace {

// Write a single line to %TEMP%\Senator.Loader.<tag>.log. Used as a proof-of-
// life signal that does NOT depend on console attach, CRT init, or any other
// runtime that might fail inside DllMain.
void WriteTag(const char* tag, const char* msg) {
    char tempDir[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tempDir);
    char path[MAX_PATH] = {};
    _snprintf_s(path, _TRUNCATE, "%sSenator.Loader.%s.log", tempDir, tag);
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{}; GetLocalTime(&st);
    char line[1024] = {};
    int n = _snprintf_s(line, _TRUNCATE,
        "%02d:%02d:%02d.%03d  pid=%lu tid=%lu  %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        GetCurrentProcessId(), GetCurrentThreadId(), msg);
    if (n > 0) {
        DWORD written = 0;
        WriteFile(h, line, (DWORD)n, &written, nullptr);
    }
    CloseHandle(h);
}

// ---------------------------------------------------------------------------
// Kernel32-only proof-of-life. NO CRT, NO globals, NO atexit. Safe to call
// from a manually-mapped image where the CRT entry was skipped.
// ---------------------------------------------------------------------------
void WriteTagRaw(const char* tag, const char* msg) {
    char tempDir[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tempDir);

    // Manual path concat: <tempDir>Senator.Loader.<tag>.log
    char path[MAX_PATH] = {};
    int pi = 0;
    for (int i = 0; tempDir[i] && pi < MAX_PATH - 1; i++) path[pi++] = tempDir[i];
    const char* p1 = "Senator.Loader.";
    for (int i = 0; p1[i] && pi < MAX_PATH - 1; i++) path[pi++] = p1[i];
    for (int i = 0; tag[i] && pi < MAX_PATH - 1; i++) path[pi++] = tag[i];
    const char* p2 = ".log";
    for (int i = 0; p2[i] && pi < MAX_PATH - 1; i++) path[pi++] = p2[i];
    path[pi] = 0;

    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st{}; GetLocalTime(&st);
    char buf[512] = {};
    // Hand-formatted: "HH:MM:SS  pid=N tid=N  msg\r\n"
    auto put2 = [&](int& off, int v) {
        if (off + 1 >= (int)sizeof(buf)) return;
        buf[off++] = (char)('0' + (v / 10) % 10);
        buf[off++] = (char)('0' + v % 10);
    };
    auto putu = [&](int& off, DWORD v) {
        char tmp[16]; int n = 0;
        if (v == 0) tmp[n++] = '0';
        else while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
        while (n > 0 && off < (int)sizeof(buf) - 1) buf[off++] = tmp[--n];
    };
    auto puts_ = [&](int& off, const char* s) {
        while (*s && off < (int)sizeof(buf) - 1) buf[off++] = *s++;
    };

    int o = 0;
    put2(o, st.wHour);   buf[o++] = ':';
    put2(o, st.wMinute); buf[o++] = ':';
    put2(o, st.wSecond); puts_(o, "  pid=");
    putu(o, GetCurrentProcessId()); puts_(o, " tid=");
    putu(o, GetCurrentThreadId()); puts_(o, "  ");
    puts_(o, msg);
    puts_(o, "\r\n");

    DWORD written = 0;
    WriteFile(h, buf, (DWORD)o, &written, nullptr);
    CloseHandle(h);
}

// Run on a dedicated worker thread so DllMain returns immediately.
DWORD WINAPI Worker(LPVOID) {
    WriteTag("worker", "worker thread started");

    // Attach to the parent process's console (the external Senator UI's
    // AllocConsole window). If that fails, allocate our own — we still want
    // diagnostics somewhere.
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();
    }
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    setvbuf(stdout, nullptr, _IONBF, 0);

    HMODULE robloxBase = GetModuleHandleA(nullptr);
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    std::fprintf(stdout,
                 "[LOADER] alive  pid=%lu  tid=%lu  base=0x%p\n",
                 pid, tid, (void*)robloxBase);

    for (int i = 1; i <= 5; i++) {
        Sleep(1000);
        std::fprintf(stdout, "[LOADER] heartbeat %d\n", i);
    }
    std::fprintf(stdout, "[LOADER] phase 1 complete (no Lua exec yet)\n");
    WriteTag("worker", "worker thread exiting cleanly");
    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Earliest possible signal that the OS actually mapped and ran us.
        // Independent of console redirection, CRT, threads, etc.
        WriteTag("dllmain", "DLL_PROCESS_ATTACH entered");
        DisableThreadLibraryCalls(hModule);
        HANDLE t = CreateThread(nullptr, 0, &Worker, nullptr, 0, nullptr);
        if (t) {
            CloseHandle(t);
            WriteTag("dllmain", "worker thread created OK");
        } else {
            char msg[128];
            _snprintf_s(msg, _TRUNCATE,
                        "CreateThread FAILED, GetLastError=%lu", GetLastError());
            WriteTag("dllmain", msg);
        }
    }
    return TRUE;
}

// ============================================================================
// CRT-free worker for the manually-mapped path. We can't safely use the CRT
// here, so everything below this line uses only kernel32 + psapi.
// ============================================================================

// Append a kernel32-only line to %TEMP%\rblx_proof.log. No CRT.
static void NeutralLog(const char* msg) {
    char tempDir[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tempDir);
    char path[MAX_PATH] = {};
    int o = 0;
    for (int i = 0; tempDir[i] && o < MAX_PATH - 1; i++) path[o++] = tempDir[i];
    const char* tail = "rblx_proof.log";
    for (int i = 0; tail[i] && o < MAX_PATH - 1; i++) path[o++] = tail[i];
    path[o] = 0;

    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st{}; GetLocalTime(&st);
    char buf[1024] = {};
    int b = 0;
    auto put2 = [&](int v) {
        if (b + 1 < (int)sizeof(buf)) {
            buf[b++] = (char)('0' + (v / 10) % 10);
            buf[b++] = (char)('0' + v % 10);
        }
    };
    auto putu = [&](DWORD v) {
        char tmp[16]; int n = 0;
        if (v == 0) tmp[n++] = '0';
        else while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
        while (n > 0 && b < (int)sizeof(buf) - 1) buf[b++] = tmp[--n];
    };
    auto puts_ = [&](const char* s) {
        while (*s && b < (int)sizeof(buf) - 1) buf[b++] = *s++;
    };
    put2(st.wHour);   buf[b++] = ':';
    put2(st.wMinute); buf[b++] = ':';
    put2(st.wSecond); puts_("  pid=");
    putu(GetCurrentProcessId()); puts_(" tid=");
    putu(GetCurrentThreadId()); puts_("  ");
    puts_(msg);
    puts_("\r\n");

    DWORD written = 0;
    WriteFile(h, buf, (DWORD)b, &written, nullptr);
    CloseHandle(h);
}

// Walk PEB->Ldr->InMemoryOrderModuleList to enumerate loaded modules without
// pulling in psapi (which has an init dependency we can't satisfy in a
// manually-mapped image).
struct UNICODE_STRING_LITE { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
struct LIST_ENTRY_LITE { LIST_ENTRY_LITE* Flink; LIST_ENTRY_LITE* Blink; };
struct LDR_ENTRY_LITE {
    LIST_ENTRY_LITE InLoadOrderLinks;
    LIST_ENTRY_LITE InMemoryOrderLinks;
    LIST_ENTRY_LITE InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_LITE FullDllName;
    UNICODE_STRING_LITE BaseDllName;
};
struct PEB_LDR_DATA_LITE {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY_LITE InLoadOrderModuleList;
    LIST_ENTRY_LITE InMemoryOrderModuleList;
    LIST_ENTRY_LITE InInitializationOrderModuleList;
};
struct PEB_LITE {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA_LITE* Ldr;
};

static PEB_LITE* CurrentPeb() {
    return (PEB_LITE*)__readgsqword(0x60);
}

static void DumpLoadedModules() {
    PEB_LITE* peb = CurrentPeb();
    if (!peb || !peb->Ldr) { NeutralLog("DumpModules: no PEB/Ldr"); return; }

    LIST_ENTRY_LITE* head = &peb->Ldr->InMemoryOrderModuleList;
    int count = 0;
    for (LIST_ENTRY_LITE* cur = head->Flink; cur != head && count < 200; cur = cur->Flink, count++) {
        // InMemoryOrderLinks is at offset 0x10 from the start of LDR_ENTRY_LITE.
        auto* entry = (LDR_ENTRY_LITE*)((BYTE*)cur - 0x10);
        if (!entry->BaseDllName.Buffer || entry->BaseDllName.Length == 0) continue;

        // BaseDllName is wide; convert ASCII-only chars (Roblox's runtime DLL
        // names are all ASCII) into a small buffer and log.
        char name[260] = {};
        int len = entry->BaseDllName.Length / 2;
        if (len > 255) len = 255;
        for (int i = 0; i < len; i++) {
            wchar_t w = entry->BaseDllName.Buffer[i];
            name[i] = (w >= 0x20 && w < 0x7F) ? (char)w : '?';
        }
        name[len] = 0;

        char line[400] = {};
        int b = 0;
        const char* prefix = "module: ";
        for (int i = 0; prefix[i]; i++) line[b++] = prefix[i];
        for (int i = 0; name[i] && b < (int)sizeof(line) - 64; i++) line[b++] = name[i];
        const char* mid = "  base=0x";
        for (int i = 0; mid[i]; i++) line[b++] = mid[i];
        // 16-char hex of base
        uintptr_t base = (uintptr_t)entry->DllBase;
        for (int s = 60; s >= 0; s -= 4) {
            int nib = (int)((base >> s) & 0xF);
            line[b++] = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
        }
        line[b] = 0;
        NeutralLog(line);
    }
    char done[64] = {};
    int b = 0;
    const char* p = "DumpModules: total=";
    for (int i = 0; p[i]; i++) done[b++] = p[i];
    char tmp[16]; int n = 0;
    int v = count;
    if (v == 0) tmp[n++] = '0';
    else while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n > 0) done[b++] = tmp[--n];
    done[b] = 0;
    NeutralLog(done);
}

// ---------------------------------------------------------------------------
// Captured symbol table. Filled by the anchor scan; consumed by TryFreshLua.
// All addresses are absolute (already relocated to live in the host process).
// ---------------------------------------------------------------------------
static struct {
    uintptr_t luaL_newstate;
    uintptr_t lua_newstate;
    uintptr_t luau_load;
    uintptr_t lua_pcall;
    uintptr_t luaopen_base;
    uintptr_t lua_newthread;
} g_syms;

static int my_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void CaptureSymbol(const char* name, uintptr_t fn) {
    if (!fn) return;
    if (my_strcmp(name, "luaL_newstate") == 0 && !g_syms.luaL_newstate) g_syms.luaL_newstate = fn;
    else if (my_strcmp(name, "lua_newstate") == 0 && !g_syms.lua_newstate) g_syms.lua_newstate = fn;
    else if (my_strcmp(name, "luau_load") == 0 && !g_syms.luau_load) g_syms.luau_load = fn;
    else if (my_strcmp(name, "lua_pcall") == 0 && !g_syms.lua_pcall) g_syms.lua_pcall = fn;
    else if (my_strcmp(name, "luaopen_base") == 0 && !g_syms.luaopen_base) g_syms.luaopen_base = fn;
    else if (my_strcmp(name, "lua_newthread") == 0 && !g_syms.lua_newthread) g_syms.lua_newthread = fn;
}

static DWORD WINAPI MmapWorker(LPVOID);

// Dump every captured Lua API address so a human can sanity-check our
// resolution. If something looks off, we don't proceed to the call.
static void DumpCapturedSymbols() {
    auto logOne = [&](const char* name, uintptr_t v) {
        char line[160] = {};
        int b = 0;
        const char* p = "sym: ";
        for (int i = 0; p[i]; i++) line[b++] = p[i];
        for (int i = 0; name[i]; i++) line[b++] = name[i];
        const char* sep = " = 0x";
        for (int i = 0; sep[i]; i++) line[b++] = sep[i];
        if (v == 0) {
            const char* z = "(not captured)";
            for (int i = 0; z[i]; i++) line[b++] = z[i];
        } else {
            for (int sh = 60; sh >= 0; sh -= 4) {
                int nib = (int)((v >> sh) & 0xF);
                line[b++] = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
            }
        }
        line[b] = 0;
        NeutralLog(line);
    };
    logOne("luaL_newstate",  g_syms.luaL_newstate);
    logOne("lua_newstate",   g_syms.lua_newstate);
    logOne("luau_load",      g_syms.luau_load);
    logOne("lua_pcall",      g_syms.lua_pcall);
    logOne("luaopen_base",   g_syms.luaopen_base);
    logOne("lua_newthread",  g_syms.lua_newthread);
}

// Sanity check: does this address sit inside an executable region of the
// host module? Catches obviously bad fn= values before we call them.
static bool IsExecutable(uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    return prot == PAGE_EXECUTE
        || prot == PAGE_EXECUTE_READ
        || prot == PAGE_EXECUTE_READWRITE
        || prot == PAGE_EXECUTE_WRITECOPY;
}

// Run a single execution attempt against an existing lua_State* using the
// bytecode in payload[]. Used by both the initial TryFreshLua and the
// per-heartbeat poll loop.
static void RunBytecode(void* L, BYTE* payload, size_t size) {
    if (!L || !payload || !size) return;
    if (!g_syms.luau_load || !IsExecutable(g_syms.luau_load) ||
        !g_syms.lua_pcall || !IsExecutable(g_syms.lua_pcall)) {
        NeutralLog("run: luau_load or lua_pcall not captured / not executable");
        return;
    }
    typedef int (*PFN_luau_load)(void*, const char*, const char*, size_t, int);
    typedef int (*PFN_lua_pcall)(void*, int, int, int);
    PFN_luau_load fn_load  = (PFN_luau_load)g_syms.luau_load;
    PFN_lua_pcall fn_pcall = (PFN_lua_pcall)g_syms.lua_pcall;

    int loadRc = -1;
    __try { loadRc = fn_load(L, "@senator", (const char*)payload, size, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NeutralLog("run: luau_load() RAISED EXCEPTION");
        return;
    }
    if (loadRc != 0) {
        char line[64] = {};
        int b = 0;
        const char* p = "run: luau_load failed rc=";
        for (int i = 0; p[i]; i++) line[b++] = p[i];
        char tmp[16]; int n = 0;
        int v = loadRc;
        bool neg = v < 0; if (neg) v = -v;
        if (v == 0) tmp[n++] = '0';
        else while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
        if (neg) line[b++] = '-';
        while (n > 0) line[b++] = tmp[--n];
        line[b] = 0;
        NeutralLog(line);
        return;
    }

    int pcallRc = -1;
    __try { pcallRc = fn_pcall(L, 0, 0, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NeutralLog("run: lua_pcall() RAISED EXCEPTION");
        return;
    }
    if (pcallRc == 0) {
        NeutralLog("run: SCRIPT EXECUTED SUCCESSFULLY");
    } else {
        char line[64] = {};
        int b = 0;
        const char* p = "run: lua_pcall rc=";
        for (int i = 0; p[i]; i++) line[b++] = p[i];
        char tmp[16]; int n = 0;
        int v = pcallRc;
        bool neg = v < 0; if (neg) v = -v;
        if (v == 0) tmp[n++] = '0';
        else while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
        if (neg) line[b++] = '-';
        while (n > 0) line[b++] = tmp[--n];
        line[b] = 0;
        NeutralLog(line);
    }
}

// Read %TEMP%\senator.luac if it exists; on success the caller is responsible
// for HeapFree(). Returns null on missing/empty/oversized.
static BYTE* ReadInbox(SIZE_T* outSize) {
    *outSize = 0;
    char tempDir[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tempDir);
    char path[MAX_PATH] = {};
    int o = 0;
    for (int i = 0; tempDir[i] && o < MAX_PATH - 1; i++) path[o++] = tempDir[i];
    const char* tail = "senator.luac";
    for (int i = 0; tail[i] && o < MAX_PATH - 1; i++) path[o++] = tail[i];
    path[o] = 0;
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return nullptr;
    LARGE_INTEGER fsize{};
    GetFileSizeEx(hf, &fsize);
    if (fsize.QuadPart <= 0 || fsize.QuadPart > 4 * 1024 * 1024) {
        CloseHandle(hf);
        return nullptr;
    }
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)fsize.QuadPart);
    DWORD got = 0;
    ReadFile(hf, buf, (DWORD)fsize.QuadPart, &got, nullptr);
    CloseHandle(hf);
    if (got != (DWORD)fsize.QuadPart) {
        HeapFree(GetProcessHeap(), 0, buf);
        return nullptr;
    }
    // Delete after read so the same file isn't replayed every heartbeat.
    DeleteFileA(path);
    *outSize = (SIZE_T)fsize.QuadPart;
    return buf;
}
//
// We expect %TEMP%\senator.luac to contain raw Luau bytecode (no RSB1 wrap;
// that's only for the Roblox ScriptContext path). The external Senator.dll
// drops a file there for us to pick up; the heartbeat loop polls.
//
// All calls are SEH-wrapped so a wrong address logs a clear failure instead
// of crashing Roblox.

// Persistent fresh state, created once by TryFreshLua and reused by the
// heartbeat poller.
static void* g_freshL = nullptr;

static void TryFreshLua() {
    if (g_freshL) return; // already created
    if (!g_syms.luaL_newstate) {
        NeutralLog("fresh-lua: luaL_newstate not captured; skipping");
        return;
    }
    if (!IsExecutable(g_syms.luaL_newstate)) {
        NeutralLog("fresh-lua: luaL_newstate fn= is not in executable memory; refusing call");
        return;
    }

    typedef void* (*PFN_luaL_newstate)();
    PFN_luaL_newstate fn_newstate = (PFN_luaL_newstate)g_syms.luaL_newstate;

    NeutralLog("fresh-lua: calling luaL_newstate()");
    void* L = nullptr;
    __try { L = fn_newstate(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NeutralLog("fresh-lua: luaL_newstate() RAISED EXCEPTION");
        return;
    }

    {
        char line[128] = {};
        int b = 0;
        const char* p = "fresh-lua: luaL_newstate() returned 0x";
        for (int i = 0; p[i]; i++) line[b++] = p[i];
        uintptr_t v = (uintptr_t)L;
        for (int sh = 60; sh >= 0; sh -= 4) {
            int nib = (int)((v >> sh) & 0xF);
            line[b++] = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
        }
        line[b] = 0;
        NeutralLog(line);
    }
    if (!L) {
        NeutralLog("fresh-lua: NULL state; cannot proceed");
        return;
    }
    g_freshL = L;

    // Optionally open the standard library so even basic scripts have print.
    if (g_syms.luaopen_base && IsExecutable(g_syms.luaopen_base)) {
        typedef int (*PFN_luaopen_base)(void*);
        PFN_luaopen_base fn = (PFN_luaopen_base)g_syms.luaopen_base;
        __try { fn(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            NeutralLog("fresh-lua: luaopen_base() RAISED EXCEPTION (ignored)");
        }
    }

    // First poll: run any payload that's already on disk before we even start
    // the heartbeat loop.
    SIZE_T sz = 0;
    BYTE* payload = ReadInbox(&sz);
    if (payload) {
        RunBytecode(L, payload, sz);
        HeapFree(GetProcessHeap(), 0, payload);
    } else {
        NeutralLog("fresh-lua: state ready, no payload yet (poll loop will pick up later writes)");
    }
}

// Called from the heartbeat loop every second.
static void PollInbox() {
    if (!g_freshL) return;
    SIZE_T sz = 0;
    BYTE* payload = ReadInbox(&sz);
    if (!payload) return;
    char msg[64] = {};
    int b = 0;
    const char* p = "poll: payload ";
    for (int i = 0; p[i]; i++) msg[b++] = p[i];
    char tmp[16]; int n = 0;
    SIZE_T v = sz;
    if (v == 0) tmp[n++] = '0';
    else while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n > 0) msg[b++] = tmp[--n];
    const char* tail = " bytes";
    for (int i = 0; tail[i]; i++) msg[b++] = tail[i];
    msg[b] = 0;
    NeutralLog(msg);
    RunBytecode(g_freshL, payload, sz);
    HeapFree(GetProcessHeap(), 0, payload);
}

// Scan RobloxPlayerBeta.exe's readable sections for known anchor strings.
// We aren't pattern-scanning code yet — strings are far more stable across
// Roblox builds and give us reliable XREF anchors for later phases.
static void ScanRobloxAnchors() {
    HMODULE host = GetModuleHandleA(nullptr);
    if (!host) { NeutralLog("anchors: GetModuleHandleA(NULL) failed"); return; }

    auto* dos = (IMAGE_DOS_HEADER*)host;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { NeutralLog("anchors: bad MZ"); return; }
    auto* nt  = (IMAGE_NT_HEADERS64*)((BYTE*)host + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { NeutralLog("anchors: bad PE"); return; }

    // Anchors we expect Roblox/Luau to emit verbatim. None are byte patterns;
    // these are plain ASCII strings, much more stable than code patterns.
    // Grouped roughly by the symbol they help us locate:
    //   error path  : luaG_typeerror, luaG_runerror
    //   loader      : luau_load, loadstring (the Lua-level wrapper)
    //   VM core     : lua_pcall, pcallk, lua_newthread, getfenv, setfenv
    //   Roblox core : ScriptContext, RBX::ScriptContext, DataModel
    //   strings     : tostring, type names that frequently appear in errors
    const char* anchors[] = {
        // --- error path ---
        "attempt to call a nil value",
        "attempt to index nil",
        "stack overflow",
        "'%s' (a %s value)",
        // --- loader / Lua-level load ---
        "luau_load",
        "loadstring",
        "Bytecode",
        // --- pcall / threads / state ---
        "lua_pcall",
        "lua_newstate",
        "lua_newthread",
        "lua_State",
        "luaopen_base",
        "luaL_newstate",
        "getfenv",
        "setfenv",
        // --- Roblox core ---
        "ScriptContext",
        "RBX::ScriptContext",
        "DataModel",
        // --- generic Luau ---
        "Luau",
    };
    constexpr int kAnchorCount = (int)(sizeof(anchors) / sizeof(anchors[0]));
    bool found[kAnchorCount] = {};
    uintptr_t foundAt[kAnchorCount] = {};

    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD si = 0; si < nt->FileHeader.NumberOfSections; si++) {
        auto& s = sections[si];
        if (!(s.Characteristics & IMAGE_SCN_MEM_READ)) continue;
        BYTE* base = (BYTE*)host + s.VirtualAddress;
        SIZE_T size = s.Misc.VirtualSize;
        if (size == 0 || size > 0x10000000) continue;

        for (SIZE_T off = 0; off < size; off++) {
            for (int a = 0; a < kAnchorCount; a++) {
                if (found[a]) continue;
                const char* needle = anchors[a];
                int nlen = 0; while (needle[nlen]) nlen++;
                if (off + nlen >= size) continue;
                bool match = true;
                for (int k = 0; k < nlen; k++) {
                    if (base[off + k] != (BYTE)needle[k]) { match = false; break; }
                }
                if (match) {
                    found[a] = true;
                    foundAt[a] = (uintptr_t)(base + off);
                    char line[300] = {};
                    int b = 0;
                    const char* p = "anchor: '";
                    for (int i = 0; p[i]; i++) line[b++] = p[i];
                    for (int i = 0; needle[i] && b < (int)sizeof(line) - 80; i++) line[b++] = needle[i];
                    const char* mid = "' @ 0x";
                    for (int i = 0; mid[i]; i++) line[b++] = mid[i];
                    uintptr_t addr = foundAt[a];
                    for (int sh = 60; sh >= 0; sh -= 4) {
                        int nib = (int)((addr >> sh) & 0xF);
                        line[b++] = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
                    }
                    line[b] = 0;
                    NeutralLog(line);
                }
            }
        }
    }

    int hits = 0;
    for (int i = 0; i < kAnchorCount; i++) if (found[i]) hits++;
    {
        char done[96] = {};
        int b = 0;
        const char* p = "anchors: hit ";
        for (int i = 0; p[i]; i++) done[b++] = p[i];
        char tmp[8]; int n = 0;
        int v = hits;
        if (v == 0) tmp[n++] = '0';
        else while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
        while (n > 0) done[b++] = tmp[--n];
        const char* sep = " of ";
        for (int i = 0; sep[i]; i++) done[b++] = sep[i];
        n = 0; v = kAnchorCount;
        if (v == 0) tmp[n++] = '0';
        else while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
        while (n > 0) done[b++] = tmp[--n];
        done[b] = 0;
        NeutralLog(done);
    }

    // Helper: walk backwards from an instruction address looking for >= 4
    // consecutive INT3 (0xCC) bytes, which is MSVC's standard inter-function
    // padding. Returns the address of the byte AFTER the padding (i.e. the
    // function entry), or 0 if we don't find padding within `maxBack` bytes.
    auto findFunctionStart = [](BYTE* sectionBase, SIZE_T sectionSize,
                                BYTE* xrefAddr, SIZE_T maxBack) -> uintptr_t {
        SIZE_T xrefOff = (SIZE_T)(xrefAddr - sectionBase);
        SIZE_T limit = (xrefOff < maxBack) ? xrefOff : maxBack;
        for (SIZE_T i = 4; i < limit; i++) {
            BYTE* p = xrefAddr - i;
            if (p[0] == 0xCC && p[1] == 0xCC && p[2] == 0xCC && p[3] == 0xCC) {
                return (uintptr_t)(p + 4);
            }
        }
        return 0;
    };

    // Back-XREF: for each anchor we found, scan executable sections for
    //   48 8D xx xx xx xx xx       lea reg, [rip+disp32]   (3-byte prefix)
    //   4C 8D xx xx xx xx xx       (with REX.R for r8-r15)
    // and check if rip + 7 + disp32 == anchor address. Log every hit with
    // surrounding bytes AND the resolved function entry so a human (or our
    // own next-phase code) can identify the calling function.
    int xrefCap = 12; // log at most 12 XREFs per anchor
    for (int a = 0; a < kAnchorCount; a++) {
        if (!found[a]) continue;
        int xrefs = 0;
        for (WORD si = 0; si < nt->FileHeader.NumberOfSections && xrefs < xrefCap; si++) {
            auto& s = sections[si];
            if (!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            BYTE* base = (BYTE*)host + s.VirtualAddress;
            SIZE_T size = s.Misc.VirtualSize;
            if (size == 0 || size > 0x10000000) continue;
            for (SIZE_T off = 0; off + 7 < size && xrefs < xrefCap; off++) {
                BYTE b0 = base[off], b1 = base[off + 1], b2 = base[off + 2];
                if ((b0 == 0x48 || b0 == 0x4C) && b1 == 0x8D) {
                    BYTE modrm = b2;
                    if ((modrm & 0xC7) != 0x05) continue; // need [rip+disp32]
                    int32_t disp = *(int32_t*)(base + off + 3);
                    uintptr_t target = (uintptr_t)(base + off) + 7 + disp;
                    if (target == foundAt[a]) {
                        // Resolve true function entry by walking back to
                        // INT3 padding. ~512 bytes back is plenty for any
                        // realistic function prologue.
                        uintptr_t entry = findFunctionStart(base, size, base + off, 512);

                        // Stash the first XREF we see for each known symbol
                        // so the execution attempt below can find addresses
                        // by name.
                        if (entry) CaptureSymbol(anchors[a], entry);

                        // Log: anchor index, instruction RIP, function entry,
                        // and the 16 bytes BEFORE the lea (the prologue tail).
                        char line[400] = {};
                        int bi = 0;
                        const char* p = "xref[";
                        for (int i = 0; p[i]; i++) line[bi++] = p[i];
                        char idx[8]; int n = 0;
                        int v = a;
                        if (v == 0) idx[n++] = '0';
                        else while (v) { idx[n++] = (char)('0' + v % 10); v /= 10; }
                        while (n > 0) line[bi++] = idx[--n];
                        const char* p2 = "] xref=0x";
                        for (int i = 0; p2[i]; i++) line[bi++] = p2[i];
                        uintptr_t rip = (uintptr_t)(base + off);
                        for (int sh = 60; sh >= 0; sh -= 4) {
                            int nib = (int)((rip >> sh) & 0xF);
                            line[bi++] = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
                        }
                        const char* pe = "  fn=0x";
                        for (int i = 0; pe[i]; i++) line[bi++] = pe[i];
                        if (entry) {
                            for (int sh = 60; sh >= 0; sh -= 4) {
                                int nib = (int)((entry >> sh) & 0xF);
                                line[bi++] = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
                            }
                        } else {
                            const char* unk = "(unknown)";
                            for (int i = 0; unk[i]; i++) line[bi++] = unk[i];
                        }
                        const char* p3 = "  prev16=";
                        for (int i = 0; p3[i]; i++) line[bi++] = p3[i];
                        int prevStart = (off >= 16) ? (int)(off - 16) : 0;
                        for (int k = prevStart; k < (int)off; k++) {
                            BYTE bb = base[k];
                            int hi = (bb >> 4) & 0xF;
                            int lo = bb & 0xF;
                            line[bi++] = (char)(hi < 10 ? '0' + hi : 'a' + (hi - 10));
                            line[bi++] = (char)(lo < 10 ? '0' + lo : 'a' + (lo - 10));
                        }
                        line[bi] = 0;
                        NeutralLog(line);
                        xrefs++;
                    }
                }
            }
        }
        if (xrefs == 0) {
            char line[128] = {};
            int bi = 0;
            const char* p = "xref[";
            for (int i = 0; p[i]; i++) line[bi++] = p[i];
            char idx[8]; int n = 0;
            int v = a;
            if (v == 0) idx[n++] = '0';
            else while (v) { idx[n++] = (char)('0' + v % 10); v /= 10; }
            while (n > 0) line[bi++] = idx[--n];
            const char* p2 = "] (no XREFs found)";
            for (int i = 0; p2[i]; i++) line[bi++] = p2[i];
            line[bi] = 0;
            NeutralLog(line);
        }
    }
}

static DWORD WINAPI MmapWorker(LPVOID) {
    NeutralLog("worker: started");
    DumpLoadedModules();
    ScanRobloxAnchors();
    DumpCapturedSymbols();
    TryFreshLua();
    // Run forever: poll the inbox every second so the external Senator.dll
    // can drop a fresh bytecode file at any time.
    int beat = 0;
    while (true) {
        Sleep(1000);
        beat++;
        PollInbox();
        // Heartbeat every 10 seconds is enough; constant logging would just
        // bloat the file.
        if (beat % 10 == 0) {
            char msg[64] = {};
            int b = 0;
            const char* p = "worker: alive (";
            for (int j = 0; p[j]; j++) msg[b++] = p[j];
            char tmp[16]; int n = 0;
            int v = beat;
            if (v == 0) tmp[n++] = '0';
            else while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
            while (n > 0) msg[b++] = tmp[--n];
            const char* tail = "s)";
            for (int j = 0; tail[j]; j++) msg[b++] = tail[j];
            msg[b] = 0;
            NeutralLog(msg);
        }
    }
    return 0;
}

// ============================================================================
// Manual-map entry point. Exported so the manual mapper can resolve it by
// name and call it instead of AddressOfEntryPoint. Uses only kernel32 — no
// CRT, no globals, no static initializers — so it survives running without
// CRT init.
// ============================================================================
extern "C" __declspec(dllexport) BOOL __stdcall ProveLife() {
    NeutralLog("ProveLife: entered");
    HANDLE t = CreateThread(nullptr, 0, &MmapWorker, nullptr, 0, nullptr);
    if (!t) {
        NeutralLog("ProveLife: CreateThread FAILED");
        return FALSE;
    }
    CloseHandle(t);
    NeutralLog("ProveLife: worker thread spawned, returning to mapper");
    return TRUE;
}
