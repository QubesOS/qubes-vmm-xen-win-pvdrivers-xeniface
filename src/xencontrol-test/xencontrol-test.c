#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>

#include "xencontrol.h"
#include "crc64.h"

#define PAGES_MIN 1
#define PAGES_MAX 64

#define PAGE_SIZE 0x1000

#define PB(va, offset)         (((BYTE *)(va)) + (offset))

// should fit in one page
typedef struct _SHARED_MEM
{
    ULONG EventPort;
    ULONG NumberPages;
    ULONG ServerPid;
    BYTE ServerFlag;
    BYTE ClientFlag;
    ULONG64 Crc;
    ULONG References[0]; // count: NumberPages
} SHARED_MEM;

#define DATA_SIZE(pages) (PAGE_SIZE*(pages) - sizeof(SHARED_MEM) - sizeof(ULONG)*(pages))
#define DATA_PTR(shm)    PB(shm, sizeof(SHARED_MEM) + (shm)->NumberPages*sizeof(ULONG))

typedef struct _EVT_CTX
{
    HANDLE MsgEvent;
    HANDLE StoreEvent;
    BOOL IsServer;
    SHARED_MEM *Shm;
    BOOL Exit;
    HANDLE Xif;
    USHORT RemoteDomain;
    USHORT LocalDomain;
} EVT_CTX;

DWORD StoreRemoteRead(HANDLE xif, ULONG serverPid, USHORT remoteDomain, USHORT localDomain);
void ReadShm(SHARED_MEM *shm);

DWORD WINAPI EventThreadProc(PVOID context)
{
    EVT_CTX *ctx = (EVT_CTX *)context;
    HANDLE events[2] = { ctx->MsgEvent, ctx->StoreEvent };
    DWORD id;

    while (TRUE)
    {
        id = WaitForMultipleObjects(2, events, FALSE, INFINITE) - WAIT_OBJECT_0;

        if (id == 0) // message event
        {
            wprintf(L"[~] msg event signaled\n");

            // check if the other peer exited
            if (ctx->IsServer)
            {
                if (ctx->Shm->ClientFlag == 0)
                {
                    wprintf(L"[~] client exited\n");
                    ctx->Exit = TRUE;
                    return 0;
                }
                if (ctx->Shm->ClientFlag == 1) // client is running
                {
                    wprintf(L"[~] client has connected\n");
                }
            }
            else // client
            {
                if (ctx->Shm->ServerFlag == 0)
                {
                    wprintf(L"[~] server exited\n");
                    ctx->Exit = TRUE;
                    return 0;
                }
            }

            ReadShm(ctx->Shm);
        }
        else if (id == 1) // store watch event
        {
            wprintf(L"[~] store watch signaled\n");
            StoreRemoteRead(ctx->Xif, ctx->Shm->ServerPid, ctx->RemoteDomain, ctx->LocalDomain);
        }
        else
        {
            wprintf(L"[!] WAIT ERROR\n");
        }
    }
}

static void ReadShm(SHARED_MEM *shm)
{
    ULONG64 crc;

    crc64(&crc, DATA_PTR(shm), DATA_SIZE(shm->NumberPages));
    wprintf(L"[=] S:%d C:%d %016I64x %s", shm->ServerFlag, shm->ClientFlag, crc, crc == shm->Crc ? L"ok\n" : L"BAD CRC\n");
}

DWORD StoreTest(IN HANDLE xif, IN ULONG serverPid, IN USHORT remoteDomain, OUT USHORT *localDomain)
{
    CHAR path[256], value[256];
    DWORD status;
    XENBUS_STORE_PERMISSION perms[2];
    DWORD pid = GetCurrentProcessId();

    StringCbPrintfA(path, sizeof(path), "name");
    status = StoreRead(xif, path, sizeof(value), value);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRead(%S) failed: 0x%x\n", path, status);
        return status;
    }
    wprintf(L"[*] StoreRead(%S): '%S'\n", path, value);

    StringCbPrintfA(path, sizeof(path), "domid");
    status = StoreRead(xif, path, sizeof(value), value);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRead(%S) failed: 0x%x\n", path, status);
        return status;
    }
    wprintf(L"[*] StoreRead(%S): '%S'\n", path, value);
    *localDomain = (USHORT)atoi(value);

    perms[0].Domain = *localDomain; // our domain
    perms[0].Mask = XENBUS_STORE_PERM_NONE; // no permissions to others
    perms[1].Domain = remoteDomain; // peer
    perms[1].Mask = XENBUS_STORE_PERM_READ;

    StringCbPrintfA(path, sizeof(path), "xiftest-%d", pid);
    StringCbPrintfA(value, sizeof(value), "this is a test");
    wprintf(L"[*] calling StoreWrite(%S, %S)\n", path, value);
    status = StoreWrite(xif, path, value);
    if (status != ERROR_SUCCESS) // this is expected
        wprintf(L"[*] StoreWrite(%S, %S) failed: 0x%x (this is expected)\n", path, value, status);

    StringCbPrintfA(path, sizeof(path), "data/xiftest-%d", pid);
    wprintf(L"[*] calling StoreWrite(%S, %S)\n", path, value);
    status = StoreWrite(xif, path, value);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreWrite(%S, %S) failed: 0x%x\n", path, value, status);
        return status;
    }

    status = StoreRead(xif, path, sizeof(value), value);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRead(%S) failed: 0x%x\n", path, status);
        return status;
    }
    wprintf(L"[*] StoreRead(%S): '%S'\n", path, value);

    status = StoreRemove(xif, path);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRemove(%S) failed: 0x%x\n", path, status);
        return status;
    }
    wprintf(L"[*] StoreRemove(%S) ok\n", path);

    // create a key readable by the peer domain
    StringCbPrintfA(path, sizeof(path), "data/xiftest-%d/%d", serverPid, remoteDomain);
    StringCbPrintfA(value, sizeof(value), "xif test %d", pid);
    status = StoreWrite(xif, path, value);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreWrite(%S, %S) failed: 0x%x\n", path, value, status);
        return status;
    }
    status = StoreSetPermissions(xif, path, 2, perms);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreSetPermissions(%S) failed: 0x%x\n", path, status);
        return status;
    }

    return ERROR_SUCCESS;
}

// read shared key
DWORD StoreRemoteRead(HANDLE xif, ULONG serverPid, USHORT remoteDomain, USHORT localDomain)
{
    CHAR path[256], value[256];
    DWORD status;

    StringCbPrintfA(path, sizeof(path), "/local/domain/%d/data/xiftest-%d/%d", remoteDomain, serverPid, localDomain);
    status = StoreRead(xif, path, sizeof(value), value);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRead(%S) failed: 0x%x\n", path, status);
        return status;
    }

    wprintf(L"[*] StoreRead(%S): '%S'\n", path, value);
    return ERROR_SUCCESS;
}

void XifLogger(XENCONTROL_LOG_LEVEL level, PCHAR function, PWCHAR format, va_list args)
{
    WCHAR buf[1024];
    StringCbVPrintf(buf, sizeof(buf), format, args);
    wprintf(L"[X] %S: %s\n", function, buf);
}

void Usage(WCHAR *exe)
{
    wprintf(L"Usage:\n");
    wprintf(L"server: %s server <remote domain id> [number of loops]\n", exe);
    wprintf(L"client: %s <remote domain id> <shared page ref> [number of loops]\n", exe);
}

int __cdecl wmain(int argc, WCHAR *argv[])
{
    HANDLE xif;
    ULONG i, loops, status;
    EVT_CTX ctx;
    SHARED_MEM *shm;
    ULONG localPort;
    PVOID watchHandle;
    CHAR storePath[256];
    ULONG seed;
    ULONG numPages;
    DWORD pid = GetCurrentProcessId();
    CHAR msg[256];
    ULONG refs[PAGES_MAX];

    if (argc < 3)
    {
        Usage(argv[0]);
        return 1;
    }

    XencontrolRegisterLogger(XifLogger);
    XencontrolSetLogLevel(XLL_DEBUG);

    status = XencontrolOpen(&xif);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] Error opening xen interface device: 0x%x\n", status);
        return 1;
    }

    ctx.MsgEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx.MsgEvent)
    {
        wprintf(L"[!] CreateEvent(msg) failed: 0x%x\n", GetLastError());
        return 1;
    }

    ctx.StoreEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx.StoreEvent)
    {
        wprintf(L"[!] CreateEvent(store) failed: 0x%x\n", GetLastError());
        return 1;
    }

    seed = GetTickCount();
    srand(seed);
    wprintf(L"[*] pid: %lu, seed: %lu\n", pid, seed);

    ctx.Exit = FALSE;
    ctx.Xif = xif;

    if (argc < 4)
        loops = 60;
    else
        loops = _wtoi(argv[3]);

    if (argv[1][0] == L's') // server
    {
        ctx.RemoteDomain = (USHORT)_wtoi(argv[2]);
        numPages = 1 + (rand() % PAGES_MAX);

        status = StoreTest(xif, pid, ctx.RemoteDomain, &ctx.LocalDomain);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] StoreTest failed: 0x%x\n", status);
            return 1;
        }

        status = EvtchnBindUnboundPort(xif, ctx.RemoteDomain, ctx.MsgEvent, FALSE, &localPort);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] EvtchnBindUnboundPort(%u) failed: 0x%x\n", ctx.RemoteDomain, status);
            return 1;
        }

        wprintf(L"[*] local event port: %lu\n", localPort);
        wprintf(L"[*] granting %lu pages to remote domain %u\n", numPages, ctx.RemoteDomain);
        status = GnttabGrantPages(xif,
                                  ctx.RemoteDomain,
                                  numPages,
                                  FIELD_OFFSET(SHARED_MEM, ServerFlag),
                                  localPort,
                                  GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET | GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT,
                                  &shm,
                                  refs);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabGrantPages failed: 0x%x\n", status);
            return 1;
        }

        shm->ServerPid = pid;
        shm->EventPort = localPort;
        shm->NumberPages = numPages;

        wprintf(L"[*] grant ok, va=%p, refs: ", shm);
        for (i = 0; i < numPages; i++)
        {
            shm->References[i] = refs[i];
            wprintf(L"%d ", refs[i]);
        }
        wprintf(L"\npress any key to continue\n");
        getc(stdin);

        ctx.Shm = shm;
        ctx.IsServer = TRUE;
        CreateThread(NULL, 0, EventThreadProc, &ctx, 0, NULL);

        // setup xenstore watch
        StringCbPrintfA(storePath, sizeof(storePath), "/local/domain/%d/data/xiftest-%d/%d", ctx.RemoteDomain, pid, ctx.LocalDomain);
        wprintf(L"[*] Adding xenstore watch on '%S'\n", storePath);
        status = StoreAddWatch(xif, storePath, ctx.StoreEvent, &watchHandle);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] StoreAddWatch failed: 0x%x\n", status);
            return 1;
        }

        // let the client know we're live
        shm->ServerFlag = 1;

        StringCbPrintfA(storePath, sizeof(storePath), "data/xiftest-%d/%d", pid, ctx.RemoteDomain);
        for (i = 0; i < loops; i++)
        {
            // write to the shared key
            StringCbPrintfA(msg, sizeof(msg), "XIFTEST %lu", i);
            StoreWrite(xif, storePath, msg); // this should cause peer's xenstore watch to fire
            // fill shared memory with random data
            for (ULONG j = 0; j < DATA_SIZE(numPages); j++)
                DATA_PTR(shm)[j] = rand() % 256;
            // update crc
            crc64(&shm->Crc, DATA_PTR(shm), DATA_SIZE(numPages));
            ReadShm(shm);
            Sleep(rand() % 1000);
            // notify the client
            EvtchnNotify(xif, localPort);
            Sleep(rand() % 1000);
            if (ctx.Exit)
                break;
        }
        ReadShm(shm);

        wprintf(L"[*] ungranting address %p\n", shm);
        status = GnttabUngrantPages(xif, shm);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabUngrantPages failed: 0x%x\n", status);
            return 1;
        }
    }
    else // client
    {
        ctx.RemoteDomain = (USHORT)_wtoi(argv[1]);
        refs[0] = _wtoi(argv[2]);
        wprintf(L"[*] performing initial one-page map: remote domain %d, ref %lu\n", ctx.RemoteDomain, refs[0]);

        status = GnttabMapForeignPages(xif,
                                       ctx.RemoteDomain,
                                       1,
                                       refs,
                                       0,
                                       0,
                                       0,
                                       &shm);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabMapForeignPages failed: 0x%x\n", status);
            return 1;
        }

        numPages = shm->NumberPages;
        wprintf(L"[*] initial map ok: va=%p, remote event port %lu, remote pid %lu, %lu refs: ",
                shm, shm->EventPort, shm->ServerPid, numPages);
        for (i = 0; i < numPages; i++)
        {
            refs[i] = shm->References[i]; // read refs for all pages and store locally since we're remapping the shared memory
            wprintf(L"%lu ", refs[i]);
        }
        wprintf(L"\n");

        status = StoreTest(xif, shm->ServerPid, ctx.RemoteDomain, &ctx.LocalDomain);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] StoreTest failed: 0x%x\n", status);
            return 1;
        }

        // bind event channel
        wprintf(L"[*] binding event channel: remote domain %d, remote port %lu\n", ctx.RemoteDomain, shm->EventPort);
        status = EvtchnBindInterdomain(xif, ctx.RemoteDomain, shm->EventPort, ctx.MsgEvent, FALSE, &localPort);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] EvtchnBindInterdomain failed: 0x%x\n", status);
            return 1;
        }
        wprintf(L"[*] local event port: %lu, remapping the full region\n", localPort);

        // unmap
        status = GnttabUnmapForeignPages(xif, shm);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabUnmapForeignPages failed: 0x%x\n", status);
            return 1;
        }

        // map the full range with notifications
        status = GnttabMapForeignPages(xif,
                                       ctx.RemoteDomain,
                                       numPages,
                                       refs,
                                       FIELD_OFFSET(SHARED_MEM, ClientFlag),
                                       localPort,
                                       GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET | GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT,
                                       &shm);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabMapForeignPages failed: 0x%x\n", status);
            return 1;
        }

        wprintf(L"[*] full map ok, va=%p\n", shm);
        ReadShm(shm);

        // setup xenstore watch
        StringCbPrintfA(storePath, sizeof(storePath), "/local/domain/%d/data/xiftest-%d/%d", ctx.RemoteDomain, shm->ServerPid, ctx.LocalDomain);
        wprintf(L"[*] Adding xenstore watch on '%S'\n", storePath);
        status = StoreAddWatch(xif, storePath, ctx.StoreEvent, &watchHandle);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] StoreAddWatch failed: 0x%x\n", status);
            return 1;
        }

        // let the server know we're live
        shm->ClientFlag = 1;
        status = EvtchnNotify(xif, localPort);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] EvtchnNotify failed: 0x%x\n", status);
            return 1;
        }

        ctx.Shm = shm;
        ctx.IsServer = FALSE;
        CreateThread(NULL, 0, EventThreadProc, &ctx, 0, NULL);

        StringCbPrintfA(storePath, sizeof(storePath), "data/xiftest-%d/%d", shm->ServerPid, ctx.RemoteDomain);
        for (i = 0; i < 60; i++)
        {
            StringCbPrintfA(msg, sizeof(msg), "XIFTEST %lu", i);
            StoreWrite(xif, storePath, msg); // this should cause peer's xenstore watch to fire
            Sleep(rand() % 1000);
            if (ctx.Exit)
                break;
        }
        ReadShm(shm);

        // final unmap
        wprintf(L"[*] unmapping address %p\n", shm);;
        status = GnttabUnmapForeignPages(xif, shm);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabUnmapForeignPages failed: 0x%x\n", status);
            return 1;
        }
    }

    status = EvtchnClose(xif, localPort);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] EvtchnClose failed: 0x%x\n", status);
        return 1;
    }

    status = StoreRemoveWatch(xif, watchHandle);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRemoveWatch failed: 0x%x\n", status);
        return 1;
    }

    wprintf(L"[*] exiting\n");

    // all handles will be closed on exit
    return 0;
}
