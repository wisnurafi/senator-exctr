#include <iostream>
#include <string>
#include <WinSock2.h>
#include "exports.h"
#include "syscalls/syscalls.h"
#include "process/scanner.h"
#include "offsets.h"
#include "execution/executor.h"
#include "execution/luau_wrapper.h"
#include "http_server.h"
#include "inject.h"
#include "instance_utils.h"
#include "manual_map.h"
#include <optional>
#include <memory>
#include <vector>
#include <cstring>
#include <algorithm>
#include <ostream>
#include <iostream>
#include <string>
#include <iomanip>
#include <filesystem>
#include <fstream>

// Internal state
static std::optional<RobloxProcess> gCore;
static uintptr_t gDataModel = 0;
static std::string gLastError;
static bool gLoaderInjected = false;
void CleanupSession(); // Forward declaration

// Resolve the path to Senator.Loader.dll. We expect it next to Senator.dll
// (UI csproj copies both into the same output directory).
static std::wstring ResolveLoaderPath() {
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&ResolveLoaderPath), &self);
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(self, buf, MAX_PATH);
    std::filesystem::path p(buf);
    p.replace_filename(L"Senator.Loader.dll");
    return p.wstring();
}

// Internal helpers
std::string InternalReadString(HANDLE h, uintptr_t address) {
    if (address < 0x10000 || address > 0x7FFFFFFFFFFF) return "";
    struct {
        union { char buffer[16]; char* ptr; };
        size_t length;
        size_t capacity;
    } strData;
    if (!ProcessScanner::ReadMemory(h, address, &strData, sizeof(strData))) return "";
    if (strData.length == 0 || strData.length > 200) return "";
    if (strData.length < 16) return std::string(strData.buffer, strData.length);
    uintptr_t dataAddr = reinterpret_cast<uintptr_t>(strData.ptr);
    std::vector<char> buffer(strData.length + 1, 0);
    if (ProcessScanner::ReadMemory(h, dataAddr, buffer.data(), strData.length)) return std::string(buffer.data(), strData.length);
    return "";
}


extern "C" {

RBLX_API bool __stdcall Initialize() {
    return SyscallResolver::Initialize();
}

RBLX_API DWORD __stdcall FindRobloxProcess() {
    auto pids = ProcessScanner::FindRobloxProcesses();
    if (pids.empty()) return 0;
    if (pids.size() == 1) return pids[0];
    
    // Multiple Roblox processes: pick the game client (most jobs)
    DWORD bestPid = 0;
    int bestJobs = 0;
    
    for (DWORD pid : pids) {
        auto proc = ProcessScanner::Connect(pid);
        if (!proc) continue;
        
        HANDLE h = proc->handle;
        uintptr_t base = proc->baseAddress;
        uintptr_t ts = ProcessScanner::Read<uintptr_t>(h, base + offsets::Pointer::TaskScheduler);
        if (!ts) continue;
        
        uintptr_t jS = ProcessScanner::Read<uintptr_t>(h, ts + offsets::TaskScheduler::JobStart);
        uintptr_t jE = ProcessScanner::Read<uintptr_t>(h, ts + offsets::TaskScheduler::JobEnd);
        int jobs = (int)((jE > jS) ? (jE - jS) / 8 : 0);
        
        if (jobs > bestJobs) {
            bestJobs = jobs;
            bestPid = pid;
        }
    }
    
    return bestPid ? bestPid : pids[0];
}

RBLX_API bool __stdcall Connect(DWORD pid) {
    gCore = ProcessScanner::Connect(pid);
    if (!gCore.has_value()) {
        gLastError = "NtOpenProcess failed for pid " + std::to_string(pid);
        std::cout << "[API] " << gLastError << "\n" << std::flush;
        return false;
    }

    ScriptExecutor::SetRobloxPid(pid);

    // Start HTTP server for Lua<->C++ communication
    if (!HttpServer::IsRunning()) {
        HttpServer::Start();
    }

    // Resolve DataModel — if this fails, offsets are almost certainly stale
    // (see README.md "Updating offsets") and there is nothing useful we can
    // do, so refuse the attach instead of pretending it worked.
    if (!gDataModel) GetDataModel();
    if (!gDataModel) {
        gLastError = "DataModel not found — offsets likely stale (see include/offsets.h)";
        std::cout << "[API] Connect FAILED: " << gLastError << "\n" << std::flush;
        gCore.reset();
        ScriptExecutor::ResetState();
        HttpServer::Stop();
        return false;
    }

    // Inject Senator.Loader.dll into Roblox via manual mapping. We use manual
    // mapping rather than LoadLibraryW because Hyperion (Roblox's anti-tamper)
    // hooks the LDR path and kills foreign threads spawned through it. Manual
    // mapping calls our loader's exported ProveLife() entrypoint directly,
    // bypassing LdrLoadDll. Whether Hyperion's thread guard fires regardless
    // is the empirical question we're answering with this attach.
    if (!gLoaderInjected) {
        std::wstring loader = ResolveLoaderPath();
        std::wcout << L"[API] Manual-mapping loader: " << loader << L"\n" << std::flush;
        if (!std::filesystem::exists(loader)) {
            gLastError = "Senator.Loader.dll not found next to Senator.dll";
            std::cout << "[API] Connect FAILED: " << gLastError << "\n" << std::flush;
            gCore.reset();
            gDataModel = 0;
            ScriptExecutor::ResetState();
            HttpServer::Stop();
            return false;
        }
        if (!inject::ManualMap(gCore->handle, loader)) {
            gLastError = "Loader manual-map failed (see [MMAP] log lines)";
            std::cout << "[API] Connect FAILED: " << gLastError << "\n" << std::flush;
            gCore.reset();
            gDataModel = 0;
            ScriptExecutor::ResetState();
            HttpServer::Stop();
            return false;
        }
        gLoaderInjected = true;
        std::cout << "[API] Loader manual-mapped\n" << std::flush;
    }

    std::cout << "[API] Connect OK (pid=" << pid << ", DataModel=0x"
              << std::hex << gDataModel << std::dec << ")\n" << std::flush;
    return true;
}

RBLX_API void __stdcall Disconnect() {
    std::cout << "[API] Disconnect called — clearing session\n" << std::flush;
    gCore.reset();
    gDataModel = 0;
    gLoaderInjected = false;
    ScriptExecutor::ResetState();
    HttpServer::Stop();
}

} // end extern "C" (temporary close for CleanupSession)

// Internal: Just reset DataModel state when leaving a server, keep the handle
void CleanupSession() {
    std::cout << "[API] Resetting session state (keeping handle)\n" << std::flush;
    gDataModel = 0;
    ScriptExecutor::ResetState();
}

extern "C" {

RBLX_API DWORD __stdcall GetRobloxPid() {
    return (gCore && gCore->pid) ? gCore->pid : 0;
}

RBLX_API void __stdcall RedirConsole() {
    // Attempt to sync with whatever console is available
    FreeConsole();
    if (AttachConsole(ATTACH_PARENT_PROCESS) || AllocConsole()) {
        FILE* f;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);

        // Disable buffering — we need every print visible immediately so that
        // when something hangs or returns early we can see exactly where.
        setvbuf(stdout, nullptr, _IONBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);

        std::ios::sync_with_stdio(true);
        std::cout.clear();
        std::cerr.clear();
        std::cout.setstate(std::ios::goodbit);
        std::cout << std::unitbuf;
        std::cerr << std::unitbuf;

        std::cout << "[DLL] Native console redirection successful\n" << std::flush;
    }
}

RBLX_API uintptr_t __stdcall GetDataModel() {
    if (!gCore || !gCore->handle) { std::cout << "[DM] No core/handle\n" << std::flush; return 0; }
    if (gDataModel) return gDataModel;

    HANDLE h = gCore->handle;
    uintptr_t base = gCore->baseAddress;
    std::cout << "[DM] Base: 0x" << std::hex << base << std::dec << "\n" << std::flush;

    // Try FakeDataModel pointer approach (proven working)
    uintptr_t fakeDM = ProcessScanner::Read<uintptr_t>(h, base + offsets::Pointer::FakeDataModelPointer);
    std::cout << "[DM] FakeDataModelPointer (base+0x" << std::hex << offsets::Pointer::FakeDataModelPointer
              << ") -> 0x" << fakeDM << std::dec << "\n" << std::flush;
    if (fakeDM) {
        uintptr_t dmCandidate = ProcessScanner::Read<uintptr_t>(h, fakeDM + offsets::FakeDataModel::DataModel);
        std::cout << "[DM]   fakeDM+0x" << std::hex << offsets::FakeDataModel::DataModel
                  << " -> 0x" << dmCandidate << std::dec << "\n" << std::flush;
        if (dmCandidate) {
            uintptr_t cd = ProcessScanner::Read<uintptr_t>(h, dmCandidate + offsets::Instance::ClassDescriptor);
            std::cout << "[DM]   ClassDescriptor: 0x" << std::hex << cd << std::dec << "\n" << std::flush;
            if (cd > 0x10000 && cd < 0x7FFFFFFFFFFF) {
                uintptr_t namePtr = ProcessScanner::Read<uintptr_t>(h, cd + offsets::Instance::ClassDescriptorToClassName);
                std::string cn = InternalReadString(h, namePtr);
                std::cout << "[DM]   ClassName: '" << cn << "'\n" << std::flush;
                if (cn == "DataModel") {
                    std::cout << "[DM] FOUND via FakeDataModel!\n" << std::flush;
                    gDataModel = dmCandidate;
                    return gDataModel;
                }
            }
        }
    }

    // Fallback: TaskScheduler job scan
    uintptr_t ts = ProcessScanner::Read<uintptr_t>(h, base + offsets::Pointer::TaskScheduler);
    std::cout << "[DM] TaskScheduler (base+0x" << std::hex << offsets::Pointer::TaskScheduler
              << ") -> 0x" << ts << std::dec << "\n" << std::flush;
    if (!ts) {
        std::cout << "[DM] FAIL: TaskScheduler pointer is null. Pointer::TaskScheduler offset is stale.\n"
                  << "[DM] FakeDataModelPointer also produced no DataModel. Update include/offsets.h\n"
                  << "     against the current Roblox version (see README.md > Updating offsets).\n"
                  << std::flush;
        return 0;
    }

    uintptr_t jS = ProcessScanner::Read<uintptr_t>(h, ts + offsets::TaskScheduler::JobStart);
    uintptr_t jE = ProcessScanner::Read<uintptr_t>(h, ts + offsets::TaskScheduler::JobEnd);
    size_t count = (jE > jS) ? (jE - jS) / 8 : 0;
    std::cout << "[DM] Job count: " << count << "\n" << std::flush;

    for (size_t i = 0; i < count; i++) {
        uintptr_t job = ProcessScanner::Read<uintptr_t>(h, jS + i * 8);
        if (!job) continue;
        
        std::vector<uintptr_t> jobMem(0x80, 0); 
        ProcessScanner::ReadMemory(h, job, jobMem.data(), jobMem.size() * 8);

        for (size_t k = 0; k < jobMem.size(); k++) {
            uintptr_t ptr = jobMem[k];
            if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF || (ptr % 8 != 0)) continue;

            uintptr_t cd = ProcessScanner::Read<uintptr_t>(h, ptr + offsets::Instance::ClassDescriptor);
            if (cd < 0x10000 || cd > 0x7FFFFFFFFFFF || (cd % 8 != 0)) continue;

            uintptr_t namePtr = ProcessScanner::Read<uintptr_t>(h, cd + offsets::Instance::ClassDescriptorToClassName);
            if (namePtr < 0x10000 || namePtr > 0x7FFFFFFFFFFF) continue;
            std::string className = InternalReadString(h, namePtr);
            if (className == "DataModel") {
                gDataModel = ptr;
                std::cout << "[DM] FOUND via job scan!\n" << std::flush;
                return gDataModel;
            }
        }
    }

    std::cout << "[DM] FAIL: neither FakeDataModel nor job scan resolved a DataModel.\n"
              << "[DM] This almost always means offsets are stale for the current Roblox build.\n"
              << "[DM] Suspect offsets to refresh first: Pointer::FakeDataModelPointer, "
              << "Pointer::TaskScheduler, FakeDataModel::DataModel, Instance::ClassDescriptor.\n"
              << std::flush;
    return 0;
}

RBLX_API int __stdcall GetJobCount() {
    if (!gCore || !gCore->handle) return -1;
    HANDLE h = gCore->handle;
    uintptr_t base = gCore->baseAddress;
    uintptr_t ts = ProcessScanner::Read<uintptr_t>(h, base + offsets::Pointer::TaskScheduler);
    if (!ts) return -1;
    uintptr_t jS = ProcessScanner::Read<uintptr_t>(h, ts + offsets::TaskScheduler::JobStart);
    uintptr_t jE = ProcessScanner::Read<uintptr_t>(h, ts + offsets::TaskScheduler::JobEnd);
    return (int)((jE - jS) / 8);
}

RBLX_API int __stdcall ExecuteScript(const char* source, int sourceLen) {
    if (!gCore || !gCore->handle) {
        gLastError = "Not connected to Roblox";
        return ScriptExecutor::ERR_NOT_CONNECTED;
    }
    if (!gLoaderInjected) {
        gLastError = "Loader DLL not injected (re-attach first)";
        return ScriptExecutor::ERR_NOT_INJECTED;
    }

    std::string src(source, sourceLen > 0 ? sourceLen : strlen(source));
    if (src.empty()) {
        gLastError = "Empty source";
        return ScriptExecutor::ERR_NO_SCRIPT_FOUND;
    }
    std::cout << "[API] ExecuteScript: " << src.size() << " bytes source\n" << std::flush;

    // Compile to raw Luau bytecode and drop it where the in-process loader
    // can find it. The loader polls %TEMP%\senator.luac at startup and on
    // every heartbeat; it'll luau_load + lua_pcall the bytes there.
    auto [ok, bytecodeOrErr] = LuauCompiler::Compile(src);
    if (!ok) {
        gLastError = "Luau compile error: " + bytecodeOrErr;
        std::cout << "[API] " << gLastError << "\n" << std::flush;
        return ScriptExecutor::ERR_COMPILE_FAILED;
    }

    wchar_t tempDir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);
    std::filesystem::path payload(tempDir);
    payload /= L"senator.luac";

    std::ofstream f(payload, std::ios::binary | std::ios::trunc);
    if (!f) {
        gLastError = "Failed to open senator.luac for writing";
        return ScriptExecutor::ERR_WRITE_FAILED;
    }
    f.write(bytecodeOrErr.data(), (std::streamsize)bytecodeOrErr.size());
    f.close();

    std::wcout << L"[API] Bytecode dropped to " << payload.wstring()
               << L" (" << bytecodeOrErr.size() << L" bytes)\n" << std::flush;
    return ScriptExecutor::SUCCESS;
}

RBLX_API int __stdcall GetLastExecError(char* buffer, int bufLen) {
    if (!buffer || bufLen <= 0) return 0;
    int copyLen = (int)std::min((size_t)bufLen - 1, gLastError.size());
    memcpy(buffer, gLastError.c_str(), copyLen);
    buffer[copyLen] = '\0';
    return copyLen;
}

RBLX_API bool __stdcall ReadMemory(uintptr_t address, void* buffer, size_t size) {
    if (!gCore || !gCore->handle) return false;
    return ProcessScanner::ReadMemory(gCore->handle, address, buffer, size);
}

RBLX_API bool __stdcall WriteMemory(uintptr_t address, const void* buffer, size_t size) {
    if (!gCore || !gCore->handle) return false;
    return ProcessScanner::WriteMemory(gCore->handle, address, buffer, size);
}

RBLX_API bool __stdcall GetClientInfo(char* buffer, int maxSize) {
    if (!gCore || !gCore->handle || !gDataModel) return false;
    HANDLE h = gCore->handle;
    
    std::string jobId = "Active";
    std::string name = "Unknown";
    std::string userId = "1";

    // Attempt to get JobId
    std::string jid = rblx::ReadRobloxString(h, gDataModel + offsets::DataModel::JobId);
    if (!jid.empty()) jobId = jid;

    // Get Players Service
    uintptr_t players = rblx::FindChildByClassName(h, gDataModel, "Players");
    if (players) {
        // Get LocalPlayer
        uintptr_t lp = ProcessScanner::Read<uintptr_t>(h, players + offsets::Players::LocalPlayer);
        if (lp) {
            std::string lpName = rblx::ReadInstanceName(h, lp);
            if (!lpName.empty()) name = lpName;
            
            uint64_t uid = ProcessScanner::Read<uint64_t>(h, lp + offsets::Player::UserId);
            if (uid > 0) userId = std::to_string(uid);
        }
    }

    std::string placeId = "0";
    uint64_t pid = ProcessScanner::Read<uint64_t>(h, gDataModel + offsets::DataModel::PlaceId);
    if (pid > 0) placeId = std::to_string(pid);

    std::string result = name + "|" + userId + "|" + jobId + "|" + placeId;
    if (result.length() >= (size_t)maxSize) return false;

    strcpy_s(buffer, maxSize, result.c_str());
    return true;
}

}
