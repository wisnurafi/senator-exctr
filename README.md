# Senator Executor

External Roblox script executor. Native C++ DLL paired with a WPF UI. Resolves Roblox's Luau API by signature scanning inside `RobloxPlayerBeta.exe` after manually mapping a small loader DLL into the process.

> Research / educational project. Use at your own risk and against your own accounts only.

## Status

The injection path works against current Hyperion-protected Roblox builds. Phase 2 (in-process script execution) resolves `luaL_newstate`, `luau_load`, and `lua_pcall` by string-anchor XREF and runs precompiled Luau bytecode against a fresh `lua_State`. Phase 3 (full game-side env, gethui/getgenv, the UNC payload) is not in this commit.

What this means in practice today:

- A successful attach manually maps `Senator.Loader.dll` into Roblox.
- The loader resolves Lua API addresses at runtime by scanning anchor strings.
- It creates a fresh, isolated `lua_State*` and runs whatever bytecode the UI drops at `%TEMP%\senator.luac`.
- The fresh state is **isolated**. It can `print` and do file I/O but does not see Roblox's `game`, `workspace`, or `Players`. Wiring the existing UNC payload into the in-process state is the next phase.

## Architecture

```
+-------------------+   P/Invoke    +------------------------+
| Senator Executor  | ------------> |  Senator.dll (native)  |
| (WPF, .NET 8)     |               |  process scan + manual |
+-------------------+               |  PE map of loader DLL  |
                                    +-----------+------------+
                                                |
                                                | manual map
                                                v
                          +---------------------+--------------------+
                          |       RobloxPlayerBeta.exe               |
                          |   +---------------------------------+    |
                          |   |  Senator.Loader.dll (mapped)    |    |
                          |   |  - PEB walk to enumerate mods   |    |
                          |   |  - anchor + back-XREF scanner   |    |
                          |   |  - resolves luau_load/lua_pcall |    |
                          |   |  - polls %TEMP%\senator.luac    |    |
                          |   |  - lua_State + luau_load+pcall  |    |
                          |   +---------------------------------+    |
                          +------------------------------------------+
```

The external DLL only does discovery + injection. Everything that touches Roblox's runtime happens inside the loader.

## Repository layout

```
include/                  Shared headers (offsets, instance helpers — legacy)
src/
  exports.cpp             DLL exported API (Initialize, Connect, ExecuteScript)
  inject.h                CreateRemoteThread + LoadLibraryW path (works only
                          on non-Hyperion targets; kept for diagnostics)
  manual_map.h            Manual PE mapping with relocations + IAT fixups
  syscalls/               Direct syscall stubs (asm + on-disk SSN resolver)
  process/                Process scanner / handle wrapper
  execution/              Luau compiler wrapper (raw Luau bytecode emit)
  http_server.h           Stub (the old HTTP-based bridge is dead;
                          phase 3 may bring it back if we need 2-way comms)
loader/
  loader.cpp              In-process worker: PEB walk, anchor + XREF scan,
                          symbol capture, fresh lua_State, bytecode runner
tools/
  loader_test.cpp         Standalone harness for inject::ManualMap. Useful
                          for testing against non-Hyperion targets like
                          winver.exe.
ui/                       WPF UI (.NET 8) + AvalonEdit
third_party/luau/         Vendored Luau Compiler/Ast/Common
CMakeLists.txt            Native build
```

## Building

Requirements:

- Windows 10/11 x64
- Visual Studio 2022 with the C++ Desktop workload (MSVC + MASM)
- CMake 3.10+ (the VS-bundled CMake works)
- .NET 8 SDK

Native (produces three artifacts):

```powershell
cmake -B build -A x64
cmake --build build --config Release
```

Outputs:
- `build\Release\Senator.dll` — external loader/injector (loaded by the WPF UI)
- `build\Release\Senator.Loader.dll` — in-process worker (manually mapped into Roblox)
- `build\Release\loader_test.exe` — diagnostic harness for the injection chain

WPF UI:

```powershell
dotnet build ui\RblxExecutorUI.csproj -c Release -p:Platform=x64
```

Outputs `ui\bin\x64\Release\net8.0-windows\Senator Executor.exe`. The csproj copies both `Senator.dll` and `Senator.Loader.dll` next to the EXE automatically.

## Running

1. Launch Roblox and join a game.
2. Run `Senator Executor.exe`.
3. Click the attach icon in the bottom-right of the status bar.
4. The console (Settings tab) will show:
   - `[API] Manual-mapping loader: ...\Senator.Loader.dll`
   - `[MMAP] image base remote=0x... size=0x...`
   - `[MMAP] using exported ProveLife @ rva=0x...`
   - `[MMAP] entry thread returned 0x...`
   - `[API] Loader manual-mapped`
5. The in-process loader writes diagnostics to `%TEMP%\rblx_proof.log`. Tail it to see the anchor scan, XREF resolution, and lua_State creation in real time.
6. Drop a script in the editor and hit Run. The compiled bytecode is written to `%TEMP%\senator.luac`, and the in-process loader picks it up on its next poll (~1s).

## Diagnostics

Two log files describe what happened:

- The Settings → Console toggle shows the external Senator.dll's stdout. Useful for the injection chain and DataModel resolution.
- `%TEMP%\rblx_proof.log` is the in-process loader's log. It includes the loaded module list, anchor matches, XREF + function-entry resolution, captured Lua API addresses, and per-script execution results.

To run the injector against a non-Hyperion process for sanity-checking:

```powershell
# Start a target
$np = Start-Process winver.exe -PassThru
# Inject manually mapped loader
.\build\Release\loader_test.exe $np.Id --mmap
# Inspect the result
Get-Content "$env:TEMP\Senator.Loader.mmap.log"
Get-Content "$env:TEMP\rblx_proof.log"
```

## Tech notes

- **Direct syscalls.** SSNs read from on-disk `ntdll.dll` to dodge user-mode hooks. See `src/syscalls/`. Used for the alloc/read/write path on the external side.
- **Manual PE mapping.** `src/manual_map.h` reads the loader DLL bytes, allocates `SizeOfImage` bytes in Roblox at any free address, copies headers + sections, applies `IMAGE_REL_BASED_DIR64` base relocations, resolves the kernel32 IAT locally, then jumps a small position-independent stub at the exported `ProveLife` symbol. Hyperion appears not to interfere because there is no `LdrLoadDll` involved.
- **In-process Luau resolution.** No hardcoded byte signatures. The loader scans `RobloxPlayerBeta.exe`'s readable sections for distinctive ASCII anchor strings (`luau_load`, `lua_pcall`, `luaL_newstate`, etc.), then back-XREFs each one looking for `lea reg, [rip+disp32]` instructions whose target is the anchor, and walks back to MSVC `INT3` padding to recover the function entry. Strings move far less often than code does, so this survives most Roblox updates.
- **Bytecode pipeline.** Luau compile via the vendored compiler with the Roblox-required `*227` opcode encoder (`src/execution/luau_wrapper.h`). The output is raw Luau bytecode (no RSB1 wrap; that's for Roblox's `ScriptContext` path which is no longer in play here).
- **IPC.** Plain file drop at `%TEMP%\senator.luac`. The loader reads, deletes, and runs. Atomic-replace via `MoveFileEx` is sufficient for our single-writer / single-reader pattern.

## What's NOT here yet

Read this carefully before opening issues.

- **No game-side env.** Scripts run in a fresh `lua_State` with whatever standard libraries `luaopen_base` provides. There is no `game`, no `workspace`, no `Players`. The compiled bytecode for `print("hi")` will work; the bytecode for `game.Players.LocalPlayer:Kick()` will fail because `game` doesn't exist in this state.
- **No UNC/SUNC API.** The big payload in `src/execution/unc_payload.h` is intact in the repo for reference. Re-injecting it into the in-process state is the next milestone, but it requires writing a Lua-side bootstrap that operates against Roblox's *real* `lua_State` (not the fresh one we make), which means hijacking the require path or finding the global state pointer.
- **No persistence across teleports.** The fresh state lives until Roblox exits. That's fine for one-shot scripts but means joining a new server requires a re-attach.

## Hyperion notes

`LoadLibraryW`-based remote injection no longer works on Roblox. The remote thread is killed mid-execution (NTSTATUS `0xC000071C` / `STATUS_INVALID_THREAD`) before `LdrLoadDll` returns. We confirmed this by injecting the same loader DLL into `winver.exe` (no Hyperion) where it runs fine, then into Roblox (Hyperion) where it dies.

Manual mapping bypasses this because there is no `LdrLoadDll` callback registered for the foreign image, and the entry-stub thread executes in code we wrote ourselves rather than in the OS loader. We do not know how long this stays viable; treat the project as research and re-test after every Roblox update.

## Updating offsets

The legacy DataModel walker still uses `include/offsets.h` to find the DataModel pointer. Most other offsets there were used by the dead static-spoof path and are now unreferenced. The single offset that matters today is `Pointer::FakeDataModelPointer`. If `[DM]` logging shows it returning 0 or the wrong ClassName, refresh from the latest rbxoffsets dump.

## Credits

- Roblox offsets: rbxoffsets.xyz auto-dump.
- Luau compiler: github.com/luau-lang/luau (vendored).

## License

No license declared. All rights reserved by the author.
