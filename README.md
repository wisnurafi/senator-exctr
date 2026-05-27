# Senator Executor

External Roblox script executor. Native C++ DLL paired with a WPF UI. Runs Luau against a live `RobloxPlayerBeta.exe` process via direct syscalls and module-script bytecode injection.

> Research / educational project. Use at your own risk and against your own accounts only.

## Architecture

```
+-------------------+         P/Invoke         +-------------------------+
|  Senator Executor | ----------------------> |  Senator.dll (native)   |
|  (WPF, .NET 8)    |                         |  syscalls + bytecode     |
+-------------------+                         +-----------+-------------+
                                                          |
                                                          | NtRead/Write/AllocVM
                                                          v
                                              +-----------+-------------+
                                              |  RobloxPlayerBeta.exe   |
                                              |  Luau VM in-process     |
                                              +-------------------------+
                                                          |
                                                          | HTTP 127.0.0.1:9753
                                                          v
                                              +-----------+-------------+
                                              |  Init Lua sandbox poll  |
                                              +-------------------------+
```

The native side resolves SSNs from on-disk `ntdll.dll`, opens the Roblox process, walks `FakeDataModel` to the `DataModel`, and overwrites a `ModuleScript` `ProtectedString` with a BLAKE3-signed, RSB1-encoded Luau bytecode blob. A spoof on `PlayerListManager` plus a synthetic `ESC` keypress triggers `require` on the patched module. The injected Lua script anchors itself in `CoreGui.Senator` and polls a localhost HTTP server for subsequent scripts so you only spoof once per session.

## Repository layout

```
include/                Shared headers (offsets, instance helpers)
src/
  exports.cpp           DLL exported API
  http_server.h         localhost HTTP server (loadstring, request, poll)
  winhttp_client.h      WinHTTP client for the /req proxy
  syscalls/             Direct syscall stubs (asm + resolver)
  process/              Process scanner / handle wrapper
  memory/               Pattern scanner / instance walker (reference)
  execution/            Compiler, RSB1 encoder, executor, UNC/SUNC payloads
ui/                     WPF UI (.NET 8)
third_party/luau/       Vendored Luau Compiler/Ast/Common
CMakeLists.txt          Native build
```

## Building

Requirements:

- Windows 10/11 x64
- Visual Studio 2022 with the C++ Desktop workload (MSVC + MASM)
- CMake 3.10+ (the VS-bundled CMake works)
- .NET 8 SDK

Native DLL:

```powershell
cmake -B build -A x64
cmake --build build --config Release
```

Outputs `build\Release\Senator.dll`.

WPF UI:

```powershell
dotnet build ui\RblxExecutorUI.csproj -c Release -p:Platform=x64
```

Outputs `ui\bin\x64\Release\net8.0-windows\Senator Executor.exe`. The csproj copies `Senator.dll` from `build\Release\` next to the EXE automatically.

## Running

1. Launch Roblox and join a game.
2. Run `Senator Executor.exe`.
3. Click the attach icon in the bottom-right of the status bar.
4. Drop your script in the editor and hit run, or pick one from the Script Hub.

Scripts placed under `ui\bin\x64\Release\net8.0-windows\Scripts\` show up automatically in the Script Hub tab.

## Updating offsets

Roblox offsets break on every update. The single source of truth is `include/offsets.h`. The values are versioned in the file's leading comment. When Roblox ships a new version, regenerate the dump and replace the constants in place; the namespace layout the codebase consumes (`offsets::Instance::Parent`, `offsets::Pointer::FakeDataModelPointer`, etc.) is stable.

A few values are not in the auto-dump and are reverse-engineered specific to this project:

- `PlayerListManager::SpoofTarget` — the slot the executor overwrites to redirect a `require` call.
- `Instance::InstanceCapabilities` — set to `0x3FFFFFFF` to spoof permissions.
- `ScriptContext::RequireBypass` — currently disabled; offset is outdated.

If injection succeeds (memory writes, ESC key, spoof revert) but the watchdog reports `Init signal timeout`, the most likely culprit is a stale `PlayerListManager::SpoofTarget`.

## Tech notes

- **Direct syscalls**: SSNs read from on-disk `ntdll.dll` to dodge user-mode hooks. See `src/syscalls/`.
- **Bytecode pipeline**: Luau compile with `opcode * 227` encoder &rarr; BLAKE3 sign with 40-byte footer &rarr; RSB1 (signature + uint32 size + ZSTD + xxHash32 XOR). See `src/execution/rsb1_encoder.h`.
- **Injection**: Spoof `PlayerListManager` target, send `ESC` to trigger menu's `require`, restore. See `src/execution/executor.h`.
- **Lua sandbox**: Init script (`executor.h::GetInitScript()` + `unc_payload.h`) sets up a UNC-style environment, anchors itself in `CoreGui.Senator`, and HTTP-polls for new scripts.
- **Cleanup**: `BindToClose`, `game.Close`, and `GameId` change all signal the C++ watchdog to restore the modified `ModuleScript` bytecode pointers and `InstanceCapabilities` so the client doesn't crash on teleport / leave.

## Credits

- Roblox offsets: rbxoffsets.xyz auto-dump.
- Bytecode pipeline reference: Xeno-style RSB1 encoder.
- Luau compiler: github.com/luau-lang/luau (vendored).

## License

No license declared. All rights reserved by the author.
