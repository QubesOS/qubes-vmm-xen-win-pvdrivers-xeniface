#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "xenctrl_native.h"
#include <strsafe.h>

#define PAGE_SIZE 0x1000
#define NUM_PAGES              4

// those are at the end of the area to test if it works ok
#define SERVER_NOTIFY_OFFSET   (NUM_PAGES*PAGE_SIZE  - 1)
#define CLIENT_NOTIFY_OFFSET   (SERVER_NOTIFY_OFFSET - 1)

#define PB(va, offset)         (((BYTE *)(va)) + (offset))
#define SERVER_FLAG(va)        (*PB(va, SERVER_NOTIFY_OFFSET))
#define CLIENT_FLAG(va)        (*PB(va, CLIENT_NOTIFY_OFFSET))

// at the start of the area so client can map/read it using just one ref
typedef struct _SHARED_MEM
{
    ULONG EventPort;
    ULONG References[NUM_PAGES];
    CHAR Message[64];
} SHARED_MEM;

typedef struct _EVT_CTX
{
    HANDLE event;
    BOOL is_server;
    PVOID va;
    BOOL exit;
} EVT_CTX;

DWORD WINAPI EventThreadProc(PVOID context)
{
    EVT_CTX *ctx = (EVT_CTX *)context;

    while (TRUE)
    {
        WaitForSingleObject(ctx->event, INFINITE);

        wprintf(L"[~] event signaled\n");

        // check if the other peer exited
        if (ctx->is_server)
        {
            if (CLIENT_FLAG(ctx->va) == 0) // client exited
            {
                wprintf(L"[~] client exited\n");
                ctx->exit = TRUE;
                return 0;
            }
            if (CLIENT_FLAG(ctx->va) == 1) // client is running
            {
                wprintf(L"[~] client has connected\n");
            }
        }
        else // client
        {
            if (SERVER_FLAG(ctx->va) == 0) // server exited
            {
                wprintf(L"[~] server exited\n");
                ctx->exit = TRUE;
                return 0;
            }
        }
    }
}

static void ReadShm(SHARED_MEM *shm)
{
    ULONG i;

    wprintf(L"[=] S:%d C:%d ", SERVER_FLAG(shm), CLIENT_FLAG(shm));

    for (i = 0; i < 16; i++)
        wprintf(L"%02x", shm->Message[i]);

    wprintf(L" ");

    for (i = 0; shm->Message[i] && (i < 16); i++)
        wprintf(L"%C", shm->Message[i]);

    wprintf(L"\n");
}

DWORD StoreTest(HANDLE xif)
{
    PCHAR path, value;
    CHAR xsBuffer[256];
    DWORD status;

    path = "name";
    status = StoreRead(xif, path, sizeof(xsBuffer), xsBuffer);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRead(%S) failed: 0x%x\n", path, status);
        return status;
    }
    wprintf(L"[*] StoreRead(%S): '%S'\n", path, xsBuffer);

    path = "domid";
    status = StoreRead(xif, path, sizeof(xsBuffer), xsBuffer);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRead(%S) failed: 0x%x\n", path, status);
        return status;
    }
    wprintf(L"[*] StoreRead(%S): '%S'\n", path, xsBuffer);

    path = "xiftest";
    value = "this is a test";
    wprintf(L"[*] calling StoreWrite(%S, %S)\n", path, value);
    status = StoreWrite(xif, path, value);
    if (status != ERROR_SUCCESS) // this is expected
        wprintf(L"[!] StoreWrite(%S, %S) failed: 0x%x\n", path, value, status);

    path = "data/xiftest";
    wprintf(L"[*] calling StoreWrite(%S, %S)\n", path, value);
    status = StoreWrite(xif, path, value);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreWrite(%S, %S) failed: 0x%x\n", path, value, status);
        return status;
    }

    status = StoreRead(xif, path, sizeof(xsBuffer), xsBuffer);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRead(%S) failed: 0x%x\n", path, status);
        return status;
    }
    wprintf(L"[*] StoreRead(%S): '%S'\n", path, xsBuffer);

    status = StoreRemove(xif, path);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] StoreRemove(%S) failed: 0x%x\n", path, status);
        return status;
    }
    wprintf(L"[*] StoreRemove(%S) ok\n", path);

    return ERROR_SUCCESS;
}

void XifLogger(XENIFACE_LOG_LEVEL level, PCHAR function, PWCHAR format, va_list args)
{
    WCHAR buf[1024];
    StringCbVPrintf(buf, sizeof(buf), format, args);
    wprintf(L"[X] %S: %s\n", function, buf);
}

int __cdecl wmain(int argc, WCHAR *argv[])
{
    HANDLE xif;
    ULONG i, loops, status;
    EVT_CTX ctx;
    SHARED_MEM *shm;
    ULONG localPort;
    USHORT remoteDomain;
    PVOID mapHandle;

    XenifaceRegisterLogger(XifLogger);
    XenifaceSetLogLevel(XLL_TRACE);

    status = XenifaceOpen(&xif);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] Error opening the device: 0x%x\n", status);
        return 1;
    }

    status = StoreTest(xif);

    ctx.event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx.event)
    {
        wprintf(L"[!] CreateEvent failed: 0x%x\n", GetLastError());
        return 1;
    }

    ctx.exit = FALSE;

    if (argc < 4)
        loops = 60;
    else
        loops = _wtoi(argv[3]);

    if (argv[1][0] == L's') // server
    {
        ULONG refs[NUM_PAGES];

        remoteDomain = (USHORT)_wtoi(argv[2]);
        status = EvtchnBindUnboundPort(xif, remoteDomain, ctx.event, FALSE, &localPort);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] EvtchnBindUnboundPort failed: 0x%x\n", status);
            return 1;
        }

        wprintf(L"[*] local event port: %lu\n", localPort);
        wprintf(L"[*] granting %d pages to remote domain %d\n", NUM_PAGES, remoteDomain);
        status = GnttabGrantPages(xif,
                                  remoteDomain,
                                  NUM_PAGES,
                                  SERVER_NOTIFY_OFFSET,
                                  localPort,
                                  GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET | GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT,
                                  &mapHandle,
                                  &shm,
                                  refs);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabGrantPages failed: 0x%x\n", status);
            return 1;
        }

        shm->EventPort = localPort;

        wprintf(L"[*] grant ok, va=%p, context %p, refs: ", shm, mapHandle);
        for (i = 0; i < NUM_PAGES; i++)
        {
            shm->References[i] = refs[i];
            wprintf(L"%d ", refs[i]);
        }
        wprintf(L"\n");

        ctx.va = shm;
        ctx.is_server = TRUE;
        CreateThread(NULL, 0, EventThreadProc, &ctx, 0, NULL);

        // let the client know we're live
        SERVER_FLAG(shm) = 1;

        ReadShm(shm);
        for (i = 0; i < loops; i++)
        {
            _snprintf(shm->Message, sizeof(shm->Message), "XIFMAP %lu", i);
            ReadShm(shm);
            Sleep(1000);
            if (ctx.exit)
                break;
        }
        ReadShm(shm);

        wprintf(L"[*] ungranting address %p, context %p\n", shm, mapHandle);
        status = GnttabUngrantPages(xif, mapHandle);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabUngrantPages failed: 0x%x\n", status);
            return 1;
        }
    }
    else // client
    {
        ULONG refs[NUM_PAGES];

        remoteDomain = (USHORT)_wtoi(argv[1]);
        refs[0] = _wtoi(argv[2]);
        wprintf(L"[*] performing initial one-page map: remote domain %d, ref %lu\n", remoteDomain, refs[0]);

        status = GnttabMapForeignPages(xif,
                                       remoteDomain,
                                       1,
                                       refs,
                                       0,
                                       0,
                                       0,
                                       &mapHandle,
                                       &shm);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabMapForeignPages failed: 0x%x\n", status);
            return 1;
        }

        wprintf(L"[*] initial map ok: va=%p, context %p, remote event port %lu, refs: ", shm, mapHandle, shm->EventPort);
        for (i = 0; i < NUM_PAGES; i++)
        {
            refs[i] = shm->References[i]; // read refs for all pages
            wprintf(L"%lu ", refs[i]);
        }
        wprintf(L"\n");

        // bind event channel
        wprintf(L"[*] binding event channel: remote domain %d, remote port %lu\n", remoteDomain, shm->EventPort);
        status = EvtchnBindInterdomain(xif, remoteDomain, shm->EventPort, ctx.event, FALSE, &localPort);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] EvtchnBindInterdomain failed: 0x%x\n", status);
            return 1;
        }
        wprintf(L"[*] local event port: %lu\n", localPort);

        // unmap
        wprintf(L"[*] remapping the full region\n");
        status = GnttabUnmapForeignPages(xif, mapHandle);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabUnmapForeignPages failed: 0x%x\n", status);
            return 1;
        }
        
        // map the full range with notifications
        status = GnttabMapForeignPages(xif,
                                       remoteDomain,
                                       NUM_PAGES,
                                       refs,
                                       CLIENT_NOTIFY_OFFSET,
                                       localPort,
                                       GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET | GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT,
                                       &mapHandle,
                                       &shm);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabMapForeignPages failed: 0x%x\n", status);
            return 1;
        }

        wprintf(L"[*] full map ok, va=%p, context %p\n", shm, mapHandle);
        ReadShm(shm);

        // let the server know we're live
        CLIENT_FLAG(shm) = 1;
        status = EvtchnNotify(xif, localPort);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] EvtchnNotify failed: 0x%x\n", status);
            return 1;
        }

        ctx.va = shm;
        ctx.is_server = FALSE;
        CreateThread(NULL, 0, EventThreadProc, &ctx, 0, NULL);

        for (i = 0; i < 60; i++)
        {
            ReadShm(shm);
            Sleep(1000);
            if (ctx.exit)
                break;
        }
        ReadShm(shm);

        // final unmap
        wprintf(L"[*] unmapping address %p, context %p\n", shm, mapHandle);;
        status = GnttabUnmapForeignPages(xif, mapHandle);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[!] GnttabUnmapForeignPages failed: 0x%x\n", status);
            return 1;
        }
    }

    // close event channel
    status = EvtchnClose(xif, localPort);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"[!] EvtchnClose failed: 0x%x\n", status);
        return 1;
    }

    wprintf(L"[*] event channel closed, exiting\n");

    // all handles will be closed on exit
    return 0;
}
