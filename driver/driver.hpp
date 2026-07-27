#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <Windows.h>
#include "NullKD/shared.h"

namespace driver {

    struct driver_get_t;
    struct exported_functions_t;
    struct s_dgx_t;

    namespace detail {
        bool send_request();
        REQUEST_DATA* get_request();
        driver_get_t& get_get_instance();
        exported_functions_t& get_exported_instance();
        s_dgx_t& get_s_dgx_instance();
    }

    struct vulnerable_t {
        uintptr_t proc_id = 0;
        uintptr_t base_address = 0;

        vulnerable_t* operator()() { return this; }

        driver_get_t& get() { return detail::get_get_instance(); }
        exported_functions_t& exported_functions() { return detail::get_exported_instance(); }
        s_dgx_t& s_dgx() { return detail::get_s_dgx_instance(); }
    };

    inline vulnerable_t vulnerable;

    struct driver_get_t {
        template<typename T>
        T read_physical_memory(uintptr_t address) {
            T value = {};
            if (!vulnerable.proc_id) return value;
            if (address == 0 || address == UINTPTR_MAX) return value;
            if (address < 0x10000ULL || address > 0x7FFFFFFFFFFFULL) return value;
            alignas(T) char buffer[sizeof(T) + 64];
            REQUEST_DATA* r = detail::get_request();
            r->magic = REQUEST_MAGIC;
            r->command = CMD_READ;
            r->pid = vulnerable.proc_id;
            r->address = address;
            r->buffer = (unsigned __int64)buffer;
            r->size = sizeof(T);
            r->result = 0;
            if (!detail::send_request()) return value;
            std::memcpy(&value, buffer, sizeof(T));
            return value;
        }

        template<typename T>
        T read_chain(uintptr_t base, const std::vector<uintptr_t>& offsets) {
            uintptr_t cur = base;
            for (size_t i = 0; i < offsets.size(); i++) {
                if (i == offsets.size() - 1)
                    return read_physical_memory<T>(cur + offsets[i]);
                cur = read_physical_memory<uintptr_t>(cur + offsets[i]);
                if (!cur || cur == UINTPTR_MAX) return T{};
            }
            return T{};
        }


        bool batch_read(BATCH_READ_REQUEST* batchReq, void* outBuf, size_t outBufSize) {
            if (!batchReq || !outBuf || outBufSize == 0) return false;
            if (!vulnerable.proc_id) return false;
            batchReq->outBuffer = (unsigned __int64)outBuf;
            REQUEST_DATA* r = detail::get_request();
            r->magic   = REQUEST_MAGIC;
            r->command = CMD_READ_BATCH;
            r->pid     = vulnerable.proc_id;
            r->address = 0;
            r->buffer  = (unsigned __int64)batchReq;
            r->size    = (unsigned __int64)outBufSize;
            r->result  = 0;
            return detail::send_request() && r->result != 0;
        }

        uintptr_t refresh(bool);
    };

    struct exported_functions_t {
        uintptr_t get_module_dll(const wchar_t* moduleName);
        uintptr_t get_process_id(const char* processName);
        uintptr_t retrieve_image_base(uintptr_t addr);
    };

    struct s_dgx_t {
        bool get_export();
    };

    std::string ReadChar(uintptr_t address);
    std::string read_wstr(uintptr_t address);
}
