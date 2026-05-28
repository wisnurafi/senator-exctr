#pragma once
// ============================================================================
// Manual PE mapping (x64).
//
// Loads a DLL into a remote process WITHOUT going through LdrLoadDll. This
// dodges anti-tamper that hooks the LDR path; it does NOT dodge anti-tamper
// that watches thread creation. Used here as an experiment to see whether
// Hyperion's foreign-thread guard fires on the LDR path or on the thread
// itself.
//
// Steps:
//   1. Read DLL bytes from disk.
//   2. Allocate SizeOfImage bytes in the target.
//   3. Write headers + each section.
//   4. Apply base relocations to account for the new base address.
//   5. Resolve imports. Loader only depends on KERNEL32, which sits at the
//      same base in every x64 process, so we resolve names locally and write
//      addresses into the remote IAT.
//   6. Build a small shellcode stub that calls DllMain(image, ATTACH, NULL).
//   7. CreateRemoteThread into the stub.
// ============================================================================

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include "syscalls/syscalls.h"

namespace inject {

inline std::vector<uint8_t> ReadFileBytes(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto size = (size_t)f.tellg();
    std::vector<uint8_t> buf(size);
    f.seekg(0);
    f.read(reinterpret_cast<char*>(buf.data()), size);
    return buf;
}

// Build a small position-independent x64 stub that calls
//   target(remoteBase, DLL_PROCESS_ATTACH, NULL)
// and returns the result via RAX. Thread start signature is DWORD WINAPI(LPVOID)
// so the lpParameter passed by CreateRemoteThread is unused; we bake all args
// into the stub instead.
//
// Layout (31 bytes):
//   48 B9 <imm64>          mov rcx, remoteBase           ; arg1 hinstDLL
//   BA 01 00 00 00         mov edx, 1                    ; arg2 DLL_PROCESS_ATTACH
//   45 31 C0               xor r8d, r8d                  ; arg3 NULL
//   48 B8 <imm64>          mov rax, target
//   FF D0                  call rax
//   C3                     ret                           ; thread exit code = EAX
inline std::vector<uint8_t> BuildEntryStub(uintptr_t remoteBase, uintptr_t target) {
    std::vector<uint8_t> stub;
    stub.reserve(31);
    auto pushImm64 = [&](uintptr_t v) {
        for (int i = 0; i < 8; i++) stub.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
    };
    // mov rcx, imm64
    stub.push_back(0x48); stub.push_back(0xB9); pushImm64(remoteBase);
    // mov edx, 1
    stub.push_back(0xBA); stub.push_back(0x01); stub.push_back(0x00); stub.push_back(0x00); stub.push_back(0x00);
    // xor r8d, r8d
    stub.push_back(0x45); stub.push_back(0x31); stub.push_back(0xC0);
    // mov rax, imm64
    stub.push_back(0x48); stub.push_back(0xB8); pushImm64(target);
    // call rax
    stub.push_back(0xFF); stub.push_back(0xD0);
    // ret
    stub.push_back(0xC3);
    return stub;
}

inline bool ManualMap(HANDLE hProcess, const std::wstring& dllPath) {
    auto image = ReadFileBytes(dllPath);
    if (image.size() < 0x200) {
        std::cout << "[MMAP] failed to read DLL bytes\n";
        return false;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { std::cout << "[MMAP] bad MZ\n"; return false; }
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { std::cout << "[MMAP] bad PE\n"; return false; }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { std::cout << "[MMAP] not x64\n"; return false; }

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    void* remoteBase = nullptr;
    SIZE_T region    = imageSize;
    NTSTATUS st = syscall::NtAllocateVirtualMemory(
        hProcess, &remoteBase, 0, &region,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (st != 0 || !remoteBase) {
        std::cout << "[MMAP] NtAllocateVirtualMemory image failed: 0x"
                  << std::hex << (uint32_t)st << std::dec << "\n";
        return false;
    }
    std::cout << "[MMAP] image base remote=0x" << std::hex << (uintptr_t)remoteBase
              << " size=0x" << imageSize << std::dec << "\n";

    // Build the local image (relocated, imports filled) in a working buffer
    // sized to SizeOfImage, then write the whole thing out at the end.
    std::vector<uint8_t> mapped(imageSize, 0);

    // Copy headers
    memcpy(mapped.data(), image.data(), nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    auto* sh = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sh[i].SizeOfRawData == 0) continue;
        memcpy(mapped.data() + sh[i].VirtualAddress,
               image.data() + sh[i].PointerToRawData,
               sh[i].SizeOfRawData);
    }

    // Apply base relocations
    uintptr_t delta = (uintptr_t)remoteBase - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto& relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relDir.Size > 0) {
            uint8_t* p   = mapped.data() + relDir.VirtualAddress;
            uint8_t* end = p + relDir.Size;
            while (p < end) {
                auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(p);
                if (block->SizeOfBlock == 0) break;
                size_t entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                auto* rel = reinterpret_cast<uint16_t*>(p + sizeof(IMAGE_BASE_RELOCATION));
                for (size_t e = 0; e < entries; e++) {
                    int type = rel[e] >> 12;
                    int off  = rel[e] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        auto* fix = reinterpret_cast<uintptr_t*>(
                            mapped.data() + block->VirtualAddress + off);
                        *fix += delta;
                    }
                    // IMAGE_REL_BASED_ABSOLUTE (0) is padding; skip silently.
                }
                p += block->SizeOfBlock;
            }
        }
    }

    // Resolve imports. Loader has only KERNEL32 imports — kernel32 sits at the
    // same base in every x64 process, so resolving locally is correct.
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size > 0) {
        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            mapped.data() + impDir.VirtualAddress);
        for (; desc->Name; desc++) {
            const char* dllName = (const char*)(mapped.data() + desc->Name);
            HMODULE mod = GetModuleHandleA(dllName);
            if (!mod) mod = LoadLibraryA(dllName);
            if (!mod) {
                std::cout << "[MMAP] failed to resolve import DLL: " << dllName << "\n";
                return false;
            }
            auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                mapped.data() + (desc->OriginalFirstThunk
                                 ? desc->OriginalFirstThunk
                                 : desc->FirstThunk));
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                mapped.data() + desc->FirstThunk);
            for (; origThunk->u1.AddressOfData; origThunk++, iat++) {
                FARPROC fn = nullptr;
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    fn = GetProcAddress(mod, MAKEINTRESOURCEA(IMAGE_ORDINAL64(origThunk->u1.Ordinal)));
                } else {
                    auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        mapped.data() + origThunk->u1.AddressOfData);
                    fn = GetProcAddress(mod, byName->Name);
                }
                if (!fn) {
                    std::cout << "[MMAP] failed to resolve import in " << dllName << "\n";
                    return false;
                }
                iat->u1.Function = (uintptr_t)fn;
            }
        }
    }

    // Find an exported function by name in the prepared image. Returns the
    // RVA, or 0 if not found.
    auto findExportRva = [&](const char* name) -> uint32_t {
        auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.Size == 0) return 0;
        auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            mapped.data() + expDir.VirtualAddress);
        auto* names    = reinterpret_cast<DWORD*>(mapped.data() + exp->AddressOfNames);
        auto* funcs    = reinterpret_cast<DWORD*>(mapped.data() + exp->AddressOfFunctions);
        auto* ordinals = reinterpret_cast<WORD*>(mapped.data() + exp->AddressOfNameOrdinals);
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const char* n = (const char*)(mapped.data() + names[i]);
            if (strcmp(n, name) == 0) return funcs[ordinals[i]];
        }
        return 0;
    };

    uint32_t proveLifeRva = findExportRva("ProveLife");
    uintptr_t entryAddr = 0;
    if (proveLifeRva) {
        entryAddr = (uintptr_t)remoteBase + proveLifeRva;
        std::cout << "[MMAP] using exported ProveLife @ rva=0x" << std::hex
                  << proveLifeRva << "  remote=0x" << entryAddr << std::dec << "\n";
    } else {
        // Fallback: AddressOfEntryPoint (DllMain via CRT). This will only
        // succeed for DLLs that don't depend on CRT init.
        entryAddr = (uintptr_t)remoteBase + nt->OptionalHeader.AddressOfEntryPoint;
        std::cout << "[MMAP] WARN: ProveLife export not found; falling back "
                     "to AddressOfEntryPoint @ 0x" << std::hex << entryAddr
                  << std::dec << "\n";
    }

    // Push the prepared image to the target.
    SIZE_T written = 0;
    st = syscall::NtWriteVirtualMemory(hProcess, remoteBase, mapped.data(),
                                       mapped.size(), &written);
    if (st != 0 || written != mapped.size()) {
        std::cout << "[MMAP] NtWriteVirtualMemory image failed: 0x"
                  << std::hex << (uint32_t)st << std::dec
                  << "  wrote " << written << "/" << mapped.size() << "\n";
        return false;
    }

    // Build entry stub and place it in remote. Allocating a separate page so
    // execution can proceed even if the image page protection later changes.
    auto stub = BuildEntryStub((uintptr_t)remoteBase, entryAddr);
    void* remoteStub = nullptr;
    SIZE_T stubSize  = stub.size();
    st = syscall::NtAllocateVirtualMemory(
        hProcess, &remoteStub, 0, &stubSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (st != 0 || !remoteStub) {
        std::cout << "[MMAP] NtAllocateVirtualMemory stub failed: 0x"
                  << std::hex << (uint32_t)st << std::dec << "\n";
        return false;
    }
    written = 0;
    st = syscall::NtWriteVirtualMemory(hProcess, remoteStub, stub.data(),
                                       stub.size(), &written);
    if (st != 0 || written != stub.size()) {
        std::cout << "[MMAP] NtWriteVirtualMemory stub failed: 0x"
                  << std::hex << (uint32_t)st << std::dec << "\n";
        return false;
    }
    std::cout << "[MMAP] entry stub remote=0x" << std::hex << (uintptr_t)remoteStub
              << "  -> entry @ 0x" << entryAddr << std::dec << "\n";

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remoteStub, nullptr, 0, nullptr);
    if (!hThread) {
        std::cout << "[MMAP] CreateRemoteThread failed: GetLastError="
                  << GetLastError() << "\n";
        return false;
    }
    DWORD wait = WaitForSingleObject(hThread, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    if (wait != WAIT_OBJECT_0) {
        std::cout << "[MMAP] entry thread did not return in 10s (waitRc=0x"
                  << std::hex << wait << std::dec << ")\n";
        return false;
    }
    std::cout << "[MMAP] entry thread returned 0x" << std::hex << exitCode << std::dec << "\n";
    return true;
}

} // namespace inject
