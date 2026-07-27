#pragma once

/*
 * shared.h - Shared definitions between kernel driver and usermode client
 *
 * This header is included by both the kernel driver (hook.cpp) and
 * the usermode test client (client.cpp). Uses only C-compatible types.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Command IDs ─────────────────────────────────────────────────── */

typedef enum _DRIVER_COMMAND {
    CMD_NONE = 0,
    CMD_READ = 1,
    CMD_WRITE = 2,
    CMD_MODULE_BASE = 3,
    CMD_ALLOC = 4,
    CMD_FREE = 5,
    CMD_PROTECT = 6,
    CMD_READ64 = 7,
    CMD_WRITE64 = 8,
    CMD_READ_BATCH = 9,   /* read multiple addresses in one kernel call */
    CMD_PING = 99,
    CMD_VERIFY_PTE = 100,
    CMD_VERIFY_SPOOF = 101,
} DRIVER_COMMAND;

/* ── Request Structure ───────────────────────────────────────────── */
/*
 * Passed as the first argument to NtQueryCompositionSurfaceStatistics.
 * The hooked function casts this to PREQUEST_DATA and dispatches.
 *
 * Magic must be set to REQUEST_MAGIC to distinguish our calls
 * from legitimate dxgkrnl calls.
 */

#define REQUEST_MAGIC 0x44524B4E  /* "DRKN" */

typedef struct _REQUEST_DATA {
    unsigned int    magic;          /* must be REQUEST_MAGIC               */
    unsigned int    command;        /* DRIVER_COMMAND                      */
    unsigned __int64 pid;           /* target process ID                   */
    unsigned __int64 address;       /* virtual address (for R/W)           */
    unsigned __int64 buffer;        /* usermode buffer address             */
    unsigned __int64 size;          /* bytes to R/W                        */
    unsigned __int64 result;        /* output: module base / alloc base    */
    unsigned int    protect;        /* memory protection (alloc/protect)   */
    wchar_t         module_name[64]; /* module name for CMD_MODULE_BASE    */
} REQUEST_DATA, *PREQUEST_DATA;

/* ── Batch Read Structures (CMD_READ_BATCH) ────────────────────────── */

#define BATCH_MAX_ENTRIES  32

/* One entry in a batch read request. outOffset is the byte offset into
   the caller-supplied output buffer where the kernel writes the result. */
typedef struct _BATCH_READ_ENTRY {
    unsigned __int64 address;   /* virtual address to read from */
    unsigned int     size;      /* bytes to read (max 64)       */
    unsigned int     outOffset; /* byte offset in output buffer */
} BATCH_READ_ENTRY, *PBATCH_READ_ENTRY;

/* Passed as the 'buffer' field of REQUEST_DATA for CMD_READ_BATCH.
   outBuffer must point to caller-allocated usermode memory >= total output size. */
typedef struct _BATCH_READ_REQUEST {
    unsigned int       count;                        /* number of entries   */
    unsigned __int64   outBuffer;                    /* usermode output ptr */
    BATCH_READ_ENTRY   entries[BATCH_MAX_ENTRIES];   /* read descriptors    */
} BATCH_READ_REQUEST, *PBATCH_READ_REQUEST;

#ifdef __cplusplus
}
#endif
