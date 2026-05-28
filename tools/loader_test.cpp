// ============================================================================
// loader_test — Standalone harness for the injector.
//
// Usage:
//   loader_test.exe <pid> [loader.dll] [--mmap]
//
// If --mmap is passed, uses inject::ManualMap (avoids LdrLoadDll). Otherwise
// uses inject::LoadLibraryRemote. Tag files in %TEMP% prove whether the
// loader's DllMain ran regardless of which mode is used.
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <cstdlib>
#include <cstring>

#include "syscalls/syscalls.h"
#include "process/scanner.h"
#include "inject.h"
#include "manual_map.h"

static std::wstring DefaultLoaderPath() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::filesystem::path p(buf);
    p.replace_filename(L"Senator.Loader.dll");
    return p.wstring();
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::wcerr << L"usage: loader_test.exe <pid> [loader.dll] [--mmap]\n";
        return 2;
    }

    DWORD pid = (DWORD)std::wcstoul(argv[1], nullptr, 10);
    if (!pid) {
        std::wcerr << L"invalid pid '" << argv[1] << L"'\n";
        return 2;
    }

    std::wstring loader;
    bool useMmap = false;
    for (int i = 2; i < argc; i++) {
        std::wstring arg = argv[i];
        if (arg == L"--mmap") useMmap = true;
        else if (loader.empty()) loader = arg;
    }
    if (loader.empty()) loader = DefaultLoaderPath();

    if (!std::filesystem::exists(loader)) {
        std::wcerr << L"loader DLL not found: " << loader << L"\n";
        return 3;
    }

    std::wcout << L"[TEST] target pid=" << pid << L"  loader=" << loader
               << L"  mode=" << (useMmap ? L"manual-map" : L"LoadLibraryW") << L"\n";

    if (!SyscallResolver::Initialize()) {
        std::wcerr << L"[TEST] SyscallResolver::Initialize failed\n";
        return 4;
    }

    auto rblx = ProcessScanner::Connect(pid);
    if (!rblx) {
        std::wcerr << L"[TEST] ProcessScanner::Connect(" << pid << L") failed\n";
        return 5;
    }

    bool ok = useMmap
        ? inject::ManualMap(rblx->handle, loader)
        : inject::LoadLibraryRemote(rblx->handle, loader);
    std::wcout << L"[TEST] inject returned " << (ok ? L"true" : L"false") << L"\n";
    std::wcout << L"[TEST] Check %TEMP%\\Senator.Loader.dllmain.log and "
                  L"Senator.Loader.worker.log for in-process proof of life.\n";
    return ok ? 0 : 1;
}
