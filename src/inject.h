#pragma once
// ============================================================================
// LoadLibrary-style DLL injector.
//
// Writes the loader DLL path into the target process, then calls
// LoadLibraryW(path) on a remote thread. We already have the target handle
// (gCore->handle) opened via direct syscall, so allocation and writing reuse
// our existing syscall layer; thread creation falls back to CreateRemoteThread
// since NtCreateThreadEx needs more args than our 6-slot DoSyscall stub.
//
// Phase 1: just inject. The loader prints a heartbeat so we can verify it
// runs. Phase 2 will resolve Roblox's Lua API from inside the loader and run
// our compiled init script directly.
// ============================================================================

#include <windows.h>
#include <string>
#include <iostream>
#include "syscalls/syscalls.h"

namespace inject {

// Translate a Win32/NT status code to a human-readable string. We try Win32
// first (LoadLibrary normally returns Win32 errors via GetLastError on the
// remote thread); if the value looks NT-shaped (top bit set) we ask ntdll.
inline std::string DescribeStatus(uint32_t code) {
    if (code == 0) return "success";
    char buf[512] = {};
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD n = FormatMessageA(flags, nullptr, code,
                             MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                             buf, sizeof(buf), nullptr);
    if (n == 0) {
        // Try the NT module if FormatMessage couldn't translate it from the
        // default tables.
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (nt) {
            n = FormatMessageA(flags | FORMAT_MESSAGE_FROM_HMODULE, nt, code,
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               buf, sizeof(buf), nullptr);
        }
    }
    std::string out;
    if (n > 0) {
        out.assign(buf, n);
        // Trim trailing newlines/CR.
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == '.' || out.back() == ' '))
            out.pop_back();
    } else {
        out = "(unknown)";
    }
    return out;
}

// Inject `dllPath` (UTF-16) into the process behind `hProcess`. Returns true
// on success and writes the loader's HMODULE to `outRemoteModule` if the
// caller cares (currently unused; useful later for unload).
inline bool LoadLibraryRemote(HANDLE hProcess, const std::wstring& dllPath,
                              uintptr_t* outRemoteModule = nullptr) {
    if (!hProcess) {
        std::cout << "[INJECT] No process handle\n";
        return false;
    }
    if (dllPath.empty()) {
        std::cout << "[INJECT] Empty DLL path\n";
        return false;
    }

    SIZE_T pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);

    // Allocate space inside Roblox for the path string.
    void* remotePath = nullptr;
    SIZE_T regionSize = pathBytes;
    NTSTATUS st = syscall::NtAllocateVirtualMemory(
        hProcess, &remotePath, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0 || !remotePath) {
        std::cout << "[INJECT] NtAllocateVirtualMemory failed: 0x"
                  << std::hex << (uint32_t)st << std::dec << "\n";
        return false;
    }

    // Write the path.
    SIZE_T written = 0;
    st = syscall::NtWriteVirtualMemory(hProcess, remotePath,
                                       (PVOID)dllPath.c_str(),
                                       pathBytes, &written);
    if (st != 0 || written != pathBytes) {
        std::cout << "[INJECT] NtWriteVirtualMemory failed: 0x"
                  << std::hex << (uint32_t)st << std::dec
                  << "  wrote " << written << "/" << pathBytes << "\n";
        return false;
    }

    // Resolve LoadLibraryW. kernel32 is at the same base in every x64 process
    // so the local address works as a remote start routine.
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE startRoutine =
        (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
    if (!startRoutine) {
        std::cout << "[INJECT] Failed to resolve LoadLibraryW\n";
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        startRoutine, remotePath, 0, nullptr);
    if (!hThread) {
        std::cout << "[INJECT] CreateRemoteThread failed: GetLastError="
                  << GetLastError() << "\n";
        return false;
    }

    // Wait for LoadLibraryW to return — the exit code is the loaded HMODULE
    // (truncated to 32 bits on x64) on success, or an NTSTATUS / Win32 error
    // on failure. The truncation matters: an HMODULE whose low 32 bits are 0
    // would look like 0; in practice that doesn't happen.
    DWORD waitRc = WaitForSingleObject(hThread, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    if (waitRc != WAIT_OBJECT_0) {
        std::cout << "[INJECT] LoadLibraryW thread did not return in 10s (waitRc=0x"
                  << std::hex << waitRc << std::dec << ")\n";
        return false;
    }

    // Heuristic: NTSTATUS error codes have the top two bits set (0xC0...).
    // Win32 errors are small positive integers. Valid HMODULE low-32 are
    // typically large but not in the 0xC000_xxxx range (Roblox's image base
    // sits around 0x7ff7_xxxx_xxxx; the low 32 bits are unrelated to that).
    bool looksLikeError = (exitCode >= 0xC0000000u && exitCode <= 0xCFFFFFFFu);
    bool looksLikeWin32Error = (exitCode >= 1 && exitCode < 0x10000u);

    if (looksLikeError || looksLikeWin32Error) {
        std::string desc = DescribeStatus(exitCode);
        std::cout << "[INJECT] LoadLibraryW FAILED. exitCode=0x"
                  << std::hex << exitCode << std::dec
                  << "  (" << desc << ")\n";
        if (outRemoteModule) *outRemoteModule = 0;
        return false;
    }

    std::cout << "[INJECT] LoadLibraryW returned 0x" << std::hex << exitCode
              << std::dec << "  (HMODULE low32, looks valid)\n";
    if (outRemoteModule) *outRemoteModule = exitCode;
    return true;
}

} // namespace inject

