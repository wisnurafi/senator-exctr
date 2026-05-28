#pragma once
// ============================================================================
// ScriptExecutor — minimal stub.
//
// History: this file used to contain a 1000+ line in-process spoof + keystroke
// trigger pipeline that overwrote a Roblox ModuleScript's bytecode pointer
// and pressed Tab/Esc to make Roblox require() it. That technique stopped
// working on modern Hyperion-protected Roblox builds: foreign threads get
// killed, and the cached require slots never re-enter even after IsLoaded is
// cleared.
//
// The new architecture lives in:
//   src/manual_map.h   — manual PE mapping into Roblox
//   loader/loader.cpp  — in-process worker that resolves luau_load / lua_pcall
//                        and runs bytecode dropped at %TEMP%\senator.luac
//
// This file is kept only because exports.cpp still uses the error codes and
// the PID/state plumbing. Everything else has been removed; do not add the
// spoof technique back.
// ============================================================================

#include <Windows.h>
#include <string>

class ScriptExecutor {
public:
    enum ErrorCode {
        SUCCESS              =  0,
        ERR_NOT_CONNECTED    = -1,
        ERR_NO_DATAMODEL     = -2,
        ERR_NO_SCRIPT_FOUND  = -3,
        ERR_COMPILE_FAILED   = -4,
        ERR_ALLOC_FAILED     = -5,
        ERR_WRITE_FAILED     = -6,
        ERR_OVERWRITE_FAILED = -7,
        ERR_INJECT_FAILED    = -8,
        ERR_NOT_INJECTED     = -9,
        ERR_TIMEOUT          = -10,
    };

    static void SetRobloxPid(DWORD pid) { sRobloxPid = pid; }
    static DWORD GetRobloxPid()         { return sRobloxPid; }

    // Reset all module-restoration state. Currently a no-op (the modules-we-
    // modified bookkeeping was tied to the dead spoof path), but kept so
    // exports.cpp can still call it during Disconnect / session cleanup.
    static void ResetState() { sRobloxPid = 0; }

private:
    static inline DWORD sRobloxPid = 0;
};
