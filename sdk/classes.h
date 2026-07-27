#pragma once
#include "math.h"
#include "decryption.h"
#include "..\driver\driver.hpp"

struct PlayerData {
    uintptr_t address;
    Vector3 position;
    std::string name;
    bool isSleeping;
    bool isValid;
};

class BaseNetworkable {
public:
    // مقدار برگشتی = valuesWrapper (برای گرفتن تعداد و آرایه)
    static uintptr_t objects_basenetworkable(uintptr_t gameAssembly) {
        if (!gameAssembly) return 0;

        uintptr_t typeInfo = gameAssembly + 0xFB99108;                 // BaseNetworkable TypeInfo RVA
        uintptr_t staticFields = driver::vulnerable()->get().read_physical_memory<uintptr_t>(typeInfo + 0xB8);
        if (!staticFields) return 0;

        uintptr_t wrapper = driver::vulnerable()->get().read_physical_memory<uintptr_t>(staticFields + 0x8);
        if (!wrapper) return 0;

        uintptr_t clientEntities = Decrypt::base_networkable_0(wrapper);
        if (!clientEntities) return 0;

        uintptr_t parentFields = driver::vulnerable()->get().read_physical_memory<uintptr_t>(clientEntities + 0x10);
        if (!parentFields) return 0;

        uintptr_t listDict = Decrypt::base_networkable_1(parentFields);
        if (!listDict) return 0;

        // valuesWrapper در listDict + 0x10
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(listDict + 0x10);
    }

    static int size_basenetworkable(uintptr_t valuesWrapper) {
        if (!valuesWrapper) return 0;
        return driver::vulnerable()->get().read_physical_memory<int>(valuesWrapper + 0x18);
    }

    static uintptr_t entity_basenetworkable(uintptr_t valuesWrapper, int i) {
        if (!valuesWrapper) return 0;
        uintptr_t array = driver::vulnerable()->get().read_physical_memory<uintptr_t>(valuesWrapper + 0x10);
        if (!array) return 0;
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(array + 0x20 + (i * 8));
    }

    static std::string GetClassName(uintptr_t entity) {
        if (!entity) return "";
        uintptr_t pKlass = driver::vulnerable()->get().read_physical_memory<uintptr_t>(entity);
        if (!pKlass) return "";
        uintptr_t pName = driver::vulnerable()->get().read_physical_memory<uintptr_t>(pKlass + 0x10);
        if (!pName) return "";
        return driver::ReadChar(pName);
    }
};

class Camera {
public:
    static uintptr_t GetMainCamera(uintptr_t gameAssembly) {
        if (!gameAssembly) return 0;

        // MainCamera TypeInfo RVA = 0xFC25F88
        uintptr_t typeInfo = gameAssembly + 0xFC25F88;
        uintptr_t staticFields = driver::vulnerable()->get().read_physical_memory<uintptr_t>(typeInfo + 0xB8);
        if (!staticFields) return 0;

        // camera_object در staticFields + 0x38
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(staticFields + 0x38);
    }

    static Matrix GetViewMatrix(uintptr_t camera) {
        if (!camera) return {};
        return driver::vulnerable()->get().read_physical_memory<Matrix>(camera + 0x2FC);
    }
};

class BasePlayer {
public:
    uintptr_t address;
    BasePlayer(uintptr_t addr) : address(addr) {}

    Vector3 GetPosition() {
        if (!address) return {0,0,0};
        uintptr_t playerModel = driver::vulnerable()->get().read_physical_memory<uintptr_t>(address + 0x520);
        if (!playerModel) return {0,0,0};
        return driver::vulnerable()->get().read_physical_memory<Vector3>(playerModel + 0x2F8);
    }

    Vector3 GetHeadPosition() {
        Vector3 pos = GetPosition();
        return Vector3(pos.x, pos.y + 1.6f, pos.z);
    }

    std::string GetName() {
        if (!address) return "";
        uintptr_t namePtr = driver::vulnerable()->get().read_physical_memory<uintptr_t>(address + 0x7B8);
        if (!namePtr || namePtr == UINTPTR_MAX || namePtr < 0x10000) return "";
        return driver::read_wstr(namePtr);
    }

    bool IsSleeping() {
        if (!address) return false;
        uint32_t flags = driver::vulnerable()->get().read_physical_memory<uint32_t>(address + 0x6B8);
        return (flags & 16) != 0;
    }

    bool IsWounded() {
        if (!address) return false;
        uint32_t flags = driver::vulnerable()->get().read_physical_memory<uint32_t>(address + 0x6B8);
        return (flags & 64) != 0;
    }

    uint64_t GetTeam() {
        if (!address) return 0;
        return driver::vulnerable()->get().read_physical_memory<uint64_t>(address + 0x538);
    }
};