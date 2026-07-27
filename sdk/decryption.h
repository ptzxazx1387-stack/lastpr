#pragma once
#include "../driver/driver.hpp"
#include <cstdint>

namespace Decrypt {
    // GCHandle → pointer
    inline uintptr_t Il2cppGetHandle(int32_t handle) {
        uintptr_t gameAssembly = driver::vulnerable()->exported_functions().get_module_dll(L"GameAssembly.dll");
        if (!gameAssembly) return 0;
        uintptr_t handleArray = driver::vulnerable()->get().read_physical_memory<uintptr_t>(gameAssembly + 0x100C22A0);
        if (!handleArray) return 0;
        uint32_t index = handle >> 3;
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(handleArray + index * 8);
    }

    // base_networkable_0 – (wrapper + 0x18)
    inline uintptr_t base_networkable_0(uintptr_t wrapper) {
        if (!wrapper) return 0;
        uintptr_t encrypted = driver::vulnerable()->get().read_physical_memory<uintptr_t>(wrapper + 0x18);
        uint32_t* p = (uint32_t*)&encrypted;
        for (int i = 0; i < 2; i++) {
            uint32_t v = p[i];
            v = (v << 16) | (v >> 16);
            v ^= 0xFE89EFE3u;
            v -= 0x7C71A258u;
            p[i] = v;
        }
        return Il2cppGetHandle(static_cast<int32_t>(encrypted));
    }

    // base_networkable_1 – (parentFields + 0x18)
    inline uintptr_t base_networkable_1(uintptr_t parentFields) {
        if (!parentFields) return 0;
        uintptr_t encrypted = driver::vulnerable()->get().read_physical_memory<uintptr_t>(parentFields + 0x18);
        uint32_t* p = (uint32_t*)&encrypted;
        for (int i = 0; i < 2; i++) {
            uint32_t v = p[i];
            v += 0xEBB43A5Au;
            v = (v << 23) | (v >> 9);
            v += 0x4A9A11E7u;
            v = (v << 28) | (v >> 4);
            p[i] = v;
        }
        return Il2cppGetHandle(static_cast<int32_t>(encrypted));
    }
}