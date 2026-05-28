#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include <algorithm>
#include "process/scanner.h"
#include "offsets.h"

namespace rblx {
    static std::string ReadRobloxString(HANDLE h, uintptr_t addr) {
        if (addr < 0x10000 || addr > 0x7FFFFFFFFFFF) return "";
        struct { union { char buf[16]; char* ptr; }; size_t length; size_t capacity; } s;
        if (!ProcessScanner::ReadMemory(h, addr, &s, sizeof(s))) return "";
        if (s.length == 0 || s.length > 200) return "";
        if (s.length < 16) {
            for (size_t i = 0; i < s.length; i++) if (s.buf[i] < 0x20 || s.buf[i] > 0x7E) return "";
            return std::string(s.buf, s.length);
        }
        uintptr_t dataAddr = reinterpret_cast<uintptr_t>(s.ptr);
        if (dataAddr < 0x10000 || dataAddr > 0x7FFFFFFFFFFF) return "";
        std::vector<char> buffer(s.length + 1, 0);
        if (ProcessScanner::ReadMemory(h, dataAddr, buffer.data(), s.length)) {
            for (size_t i = 0; i < s.length; i++) if (buffer[i] < 0x20 || buffer[i] > 0x7E) return "";
            return std::string(buffer.data(), s.length);
        }
        return "";
    }

    static std::string ReadInstanceName(HANDLE h, uintptr_t inst) {
        uintptr_t ptr = ProcessScanner::Read<uintptr_t>(h, inst + offsets::Instance::Name);
        std::string s = ReadRobloxString(h, ptr);
        if (!s.empty()) return s;
        for (size_t off : {(size_t)0xA8, (size_t)0x50, (size_t)0x48}) {
            ptr = ProcessScanner::Read<uintptr_t>(h, inst + off);
            s = ReadRobloxString(h, ptr);
            if (!s.empty()) return s;
        }
        return "";
    }

    static std::string ReadClassName(HANDLE h, uintptr_t inst) {
        uintptr_t cd = ProcessScanner::Read<uintptr_t>(h, inst + offsets::Instance::ClassDescriptor);
        if (cd < 0x10000 || cd > 0x7FFFFFFFFFFF) return "";
        uintptr_t namePtr = ProcessScanner::Read<uintptr_t>(h, cd + offsets::Instance::ClassDescriptorToClassName);
        return ReadRobloxString(h, namePtr);
    }

    static bool IsValidInstance(HANDLE h, uintptr_t ptr) {
        if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) return false;
        uintptr_t cd = ProcessScanner::Read<uintptr_t>(h, ptr + offsets::Instance::ClassDescriptor);
        return (cd >= 0x10000 && cd <= 0x7FFFFFFFFFFF);
    }

    static std::vector<uintptr_t> GetChildren(HANDLE h, uintptr_t instance) {
        if (!IsValidInstance(h, instance)) return {};

        // Roblox uses two layouts for the children vector depending on the
        // instance class:
        //   A) Inline std::vector embedded in the Instance:
        //        begin = *(instance + off)
        //        end   = *(instance + off + 8)
        //   B) Heap-allocated children container, accessed through a pointer:
        //        containerPtr = *(instance + off)
        //        begin = *containerPtr
        //        end   = *(containerPtr + 8)
        // Each entry in either layout is std::shared_ptr<Instance> (16 bytes;
        // raw Instance* lives at +0).
        constexpr size_t kEntryStride = 16;

        auto readVector = [&](uintptr_t startNode, uintptr_t endNode) -> std::vector<uintptr_t> {
            if (startNode < 0x10000 || startNode > 0x7FFFFFFFFFFF) return {};
            if (endNode   < startNode) return {};
            if ((startNode % 8) != 0) return {};

            size_t byteRange = endNode - startNode;
            if (byteRange == 0)               return {};
            if (byteRange % kEntryStride != 0) return {};
            if (byteRange > 0x100000)         return {};

            size_t nodeCount = byteRange / kEntryStride;

            int probeCount = (int)std::min(nodeCount, (size_t)4);
            int valid = 0;
            for (int i = 0; i < probeCount; i++) {
                uintptr_t child = ProcessScanner::Read<uintptr_t>(h, startNode + i * kEntryStride);
                if (IsValidInstance(h, child)) valid++;
            }
            if (valid == 0) return {};

            std::vector<uintptr_t> children;
            children.reserve(nodeCount);
            for (size_t i = 0; i < nodeCount; i++) {
                uintptr_t child = ProcessScanner::Read<uintptr_t>(h, startNode + i * kEntryStride);
                if (child && IsValidInstance(h, child)) children.push_back(child);
            }
            return children;
        };

        // Inline layout: begin/end are stored directly in the Instance.
        {
            uintptr_t startNode = ProcessScanner::Read<uintptr_t>(h, instance + offsets::Instance::Children);
            uintptr_t endNode   = ProcessScanner::Read<uintptr_t>(h, instance + offsets::Instance::Children + 8);
            auto out = readVector(startNode, endNode);
            if (!out.empty()) return out;
        }

        // Heap layout: the slot holds a pointer to a {begin,end} struct.
        {
            uintptr_t containerPtr = ProcessScanner::Read<uintptr_t>(h, instance + offsets::Instance::Children);
            if (containerPtr >= 0x10000 && containerPtr <= 0x7FFFFFFFFFFF && (containerPtr % 8) == 0) {
                uintptr_t startNode = ProcessScanner::Read<uintptr_t>(h, containerPtr);
                uintptr_t endNode   = ProcessScanner::Read<uintptr_t>(h, containerPtr + 8);
                auto out = readVector(startNode, endNode);
                if (!out.empty()) return out;
            }
        }

        // Empty children is a legitimate answer for many instance kinds (most
        // GUI leaf nodes, scripts that haven't been parented anything, etc.).
        // Do NOT fall back to scanning random offsets — that will latch onto
        // unrelated memory that happens to look like a vector and cause
        // descendant searches to wander through garbage.
        return {};
    }

    static uintptr_t FindChildByName(HANDLE h, uintptr_t parent, const std::string& name) {
        for (auto child : GetChildren(h, parent))
            if (ReadInstanceName(h, child) == name) return child;
        return 0;
    }

    static uintptr_t FindChildByClassName(HANDLE h, uintptr_t parent, const std::string& cls) {
        for (auto child : GetChildren(h, parent))
            if (ReadClassName(h, child) == cls) return child;
        return 0;
    }

    static std::vector<std::string> GetFullInstancePath(HANDLE h, uintptr_t inst) {
        std::vector<std::string> path;
        path.push_back(ReadInstanceName(h, inst));
        uintptr_t current = inst;
        for (int i = 0; i < 20; i++) {
            uintptr_t parent = ProcessScanner::Read<uintptr_t>(h, current + offsets::Instance::Parent);
            if (!parent || !IsValidInstance(h, parent)) break;

            // Stop if parent is the DataModel (its parent is null)
            uintptr_t parentOfParent = ProcessScanner::Read<uintptr_t>(h, parent + offsets::Instance::Parent);
            if (!parentOfParent) break;

            std::string name = ReadInstanceName(h, parent);
            if (name == "Game" || name == "game" || name.empty()) break;
            
            path.insert(path.begin(), name);
            current = parent;
        }
        path.insert(path.begin(), "game");
        return path;
    }
}

