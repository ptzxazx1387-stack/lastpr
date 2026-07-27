/*
 * driver.cpp - Usermode client for NullKD driver
 */

#include "driver.hpp"
#include "NullKD/shared.h"
#include <cstring>
#include <TlHelp32.h>
#include <mutex>

#ifndef _NTDEF_
typedef long NTSTATUS;
#endif

#pragma comment(lib, "ntdll.lib")

namespace driver {

    using NtQueryCompositionSurfaceStatistics_t = NTSTATUS(NTAPI*)(void* param1, void* param2, void* param3);

    static NtQueryCompositionSurfaceStatistics_t g_NtQuery = nullptr;
    static thread_local REQUEST_DATA g_req;  /* per-thread: no mutex needed, zero contention */
    static driver_get_t s_get;
    static exported_functions_t s_exported_instance;
    static s_dgx_t s_s_dgx_instance;

    static bool resolve_driver_export() {
        if (g_NtQuery) return true;
        HMODULE hWin32u = GetModuleHandleA("win32u.dll");
        if (!hWin32u) hWin32u = LoadLibraryA("win32u.dll");
        if (!hWin32u) return false;
        g_NtQuery = (NtQueryCompositionSurfaceStatistics_t)GetProcAddress(hWin32u, "NtQueryCompositionSurfaceStatistics");
        return g_NtQuery != nullptr;
    }

    namespace detail {
        bool send_request() {
            if (!resolve_driver_export() || !g_NtQuery) return false;
            g_req.magic = REQUEST_MAGIC;
            NTSTATUS status = 1;
            __try {
                status = g_NtQuery(&g_req, nullptr, nullptr);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
            return (status == 0 || status == 1);
        }
        REQUEST_DATA* get_request() { return &g_req; }
        driver_get_t& get_get_instance() { return s_get; }
        exported_functions_t& get_exported_instance() { return s_exported_instance; }
        s_dgx_t& get_s_dgx_instance() { return s_s_dgx_instance; }
    }

    uintptr_t driver_get_t::refresh(bool) {
        vulnerable.base_address = s_exported_instance.retrieve_image_base(0);
        return vulnerable.base_address;
    }

    uintptr_t exported_functions_t::get_module_dll(const wchar_t* moduleName) {
        if (!vulnerable.proc_id) return 0;
        REQUEST_DATA* r = detail::get_request();
        wcsncpy_s(r->module_name, moduleName, 63);
        r->module_name[63] = L'\0';
        r->magic = REQUEST_MAGIC;
        r->command = CMD_MODULE_BASE;
        r->pid = vulnerable.proc_id;
        r->result = 0;
        if (!detail::send_request()) return 0;
        return (uintptr_t)r->result;
    }

    uintptr_t exported_functions_t::get_process_id(const char* processName) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName) == 0) {
                    CloseHandle(snap);
                    return (uintptr_t)pe.th32ProcessID;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        return 0;
    }

    uintptr_t exported_functions_t::retrieve_image_base(uintptr_t addr) {
        if (addr) return addr;
        if (!vulnerable.proc_id) return 0;
        uintptr_t base = get_module_dll(L"RustClient.exe");
        if (base) vulnerable.base_address = base;
        return base;
    }

    bool s_dgx_t::get_export() {
        if (!resolve_driver_export()) return false;
        REQUEST_DATA* r = detail::get_request();
        r->magic = REQUEST_MAGIC;
        r->command = CMD_PING;
        r->result = 0;
        detail::send_request();
        return r->result != 0;
    }

    std::string ReadChar(uintptr_t address) {
        std::string out;
        if (!vulnerable.proc_id) return out;
        if (address == 0 || address == UINTPTR_MAX) return out;
        if (address < 0x10000ULL || address > 0x7FFFFFFFFFFFULL) return out;
        char c;
        const size_t maxLen = 256;
        for (size_t i = 0; i < maxLen; i++) {
            REQUEST_DATA* r = detail::get_request();
            r->magic = REQUEST_MAGIC;
            r->command = CMD_READ;
            r->pid = vulnerable.proc_id;
            r->address = address + i;
            r->buffer = (unsigned __int64)&c;
            r->size = 1;
            r->result = 0;
            if (!detail::send_request()) break;
            if (c == '\0') break;
            out += c;
        }
        return out;
    }

    std::string read_wstr(uintptr_t address) {
        std::string out;
        if (!vulnerable.proc_id) return out;
        if (address == 0 || address == UINTPTR_MAX) return out;
        if (address < 0x10000ULL || address > 0x7FFFFFFFFFFFULL) return out;
        wchar_t wbuf[128] = {};
        const size_t maxW = 127;
        size_t i = 0;
        for (; i < maxW; i++) {
            REQUEST_DATA* r = detail::get_request();
            r->magic = REQUEST_MAGIC;
            r->command = CMD_READ;
            r->pid = vulnerable.proc_id;
            r->address = address + i * sizeof(wchar_t);
            r->buffer = (unsigned __int64)(&wbuf[i]);
            r->size = sizeof(wchar_t);
            r->result = 0;
            if (!detail::send_request()) break;
            if (wbuf[i] == L'\0') break;
        }
        wbuf[i] = L'\0';
        for (const wchar_t* p = wbuf; *p; p++) {
            if (*p < 128) out += (char)*p;
            else out += '?';
        }
        return out;
    }
}
