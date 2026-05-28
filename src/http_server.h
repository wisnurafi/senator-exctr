#pragma once
// ============================================================================
// HttpServer — minimal stub.
//
// The original implementation hosted /ls /req /exec /poll /cleanup endpoints
// for the Roblox-side init script to talk back to the external DLL. That
// architecture is dead (see executor.h header for the explanation); the new
// loader runs in-process and consumes a file drop at %TEMP%\senator.luac.
//
// We keep this header so exports.cpp can still call HttpServer::Start /
// IsRunning / Stop without #ifdefs. They're now no-ops.
// ============================================================================

namespace HttpServer {
    inline bool sRunning = false;

    inline void Start() { sRunning = true; }
    inline void Stop()  { sRunning = false; }
    inline bool IsRunning() { return sRunning; }
}
