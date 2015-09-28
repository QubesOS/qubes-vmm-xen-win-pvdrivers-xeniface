#define INITGUID
#include "xencontrol.h"

#include <stdlib.h>
#include <setupapi.h>
#include <assert.h>

static XenifaceLogger *g_Logger = NULL;
static XENIFACE_LOG_LEVEL g_LogLevel = XLL_INFO;
static ULONG g_RequestId = 1;

#define Log(level, format, ...) _Log(level, __FUNCTION__, format, __VA_ARGS__)

#if defined (_DEBUG) || defined(DEBUG) || defined(DBG)
#   define FUNCTION_ENTER() _Log(XLL_TRACE, __FUNCTION__, L"-->")
#   define FUNCTION_EXIT() _Log(XLL_TRACE, __FUNCTION__, L"<--")
#else
#   define FUNCTION_ENTER()
#   define FUNCTION_EXIT()
#endif

#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }

typedef struct _XENCONTROL_GNTTAB_REQUEST
{
    LIST_ENTRY ListEntry;
    OVERLAPPED Overlapped;
    ULONG Id;
    PVOID Address;
} XENCONTROL_GNTTAB_REQUEST, *PXENCONTROL_GNTTAB_REQUEST;

static LIST_ENTRY g_RequestList;
static CRITICAL_SECTION g_RequestListLock;

static PXENCONTROL_GNTTAB_REQUEST
FindRequest(
    IN  PVOID Address
    )
{
    PLIST_ENTRY entry;
    PXENCONTROL_GNTTAB_REQUEST returnRequest = NULL;

    EnterCriticalSection(&g_RequestListLock);
    entry = g_RequestList.Flink;
    while (entry != &g_RequestList)
    {
        PXENCONTROL_GNTTAB_REQUEST request = CONTAINING_RECORD(entry, XENCONTROL_GNTTAB_REQUEST, ListEntry);
        if (request->Address == Address)
        {
            returnRequest = request;
            break;
        }

        entry = entry->Flink;
    }
    LeaveCriticalSection(&g_RequestListLock);

    return returnRequest;
}

BOOL APIENTRY DllMain(HMODULE module,
                      DWORD reasonForCall,
                      LPVOID reserved)
{
    switch (reasonForCall)
    {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&g_RequestListLock);
        InitializeListHead(&g_RequestList);
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void XenifaceSetLogLevel(
    IN  XENIFACE_LOG_LEVEL logLevel
    )
{
    g_LogLevel = logLevel;
}

static void _Log(
    IN  XENIFACE_LOG_LEVEL logLevel,
    IN  PCHAR function,
    IN  PWCHAR format,
    ...
    )
{
    va_list args;
    DWORD lastError;

    if (!g_Logger)
        return;

    if (logLevel > g_LogLevel)
        return;

    lastError = GetLastError();
    va_start(args, format);
    g_Logger(logLevel, function, format, args);
    va_end(args);
    SetLastError(lastError);
}

static void
LogMultiSz(
    IN  PCHAR Caller,
    IN  XENIFACE_LOG_LEVEL Level,
    IN  PCHAR MultiSz
    )
{
    PCHAR Ptr;
    ULONG Len;

    for (Ptr = MultiSz; *Ptr;)
    {
        Len = (ULONG)strlen(Ptr);
        _Log(Level, Caller, L"%S", Ptr);
        Ptr += (Len + 1);
    }
}

void XenifaceRegisterLogger(
    IN  XenifaceLogger *logger
    )
{
    FUNCTION_ENTER();
    g_Logger = logger;
    FUNCTION_EXIT();
}

DWORD XenifaceOpen(
    OUT HANDLE *iface
    )
{
    HDEVINFO devInfo;
    SP_DEVICE_INTERFACE_DATA sdid;
    SP_DEVICE_INTERFACE_DETAIL_DATA *sdidd = NULL;
    DWORD bufferSize;

    FUNCTION_ENTER();

    devInfo = SetupDiGetClassDevs(&GUID_INTERFACE_XENIFACE, 0, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devInfo == INVALID_HANDLE_VALUE)
    {
        Log(XLL_ERROR, L"XENIFACE device class doesn't exist");
        goto fail;
    }

    sdid.cbSize = sizeof(sdid);
    if (!SetupDiEnumDeviceInterfaces(devInfo, NULL, &GUID_INTERFACE_XENIFACE, 0, &sdid))
    {
        Log(XLL_ERROR, L"Failed to enumerate XENIFACE devices");
        goto fail;
    }

    SetupDiGetDeviceInterfaceDetail(devInfo, &sdid, NULL, 0, &bufferSize, NULL);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        Log(XLL_ERROR, L"Failed to get buffer size for device details");
        goto fail;
    }

    // Using 'bufferSize' from failed function call
    // ...yeah, that's the point
#pragma warning(suppress: 6102)
    sdidd = (SP_DEVICE_INTERFACE_DETAIL_DATA *)malloc(bufferSize);
    if (!sdidd)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    sdidd->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

    if (!SetupDiGetDeviceInterfaceDetail(devInfo, &sdid, sdidd, bufferSize, NULL, NULL))
    {
        Log(XLL_ERROR, L"Failed to get XENIFACE device path");
        goto fail;
    }

    *iface = CreateFile(sdidd->DevicePath,
                        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                        0,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                        NULL);

    if (*iface == INVALID_HANDLE_VALUE)
    {
        Log(XLL_ERROR, L"Failed to open XENIFACE device, path: %s", sdidd->DevicePath);
        goto fail;
    }

    Log(XLL_DEBUG, L"Device handle: 0x%x", *iface);

    free(sdidd);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    free(sdidd);
    FUNCTION_EXIT();
    return GetLastError();
}

void XenifaceClose(
    IN  HANDLE iface
    )
{
    FUNCTION_ENTER();
    CloseHandle(iface);
    FUNCTION_EXIT();
}

DWORD EvtchnBindUnboundPort(
    IN  HANDLE iface,
    IN  USHORT remoteDomain,
    IN  HANDLE event,
    IN  BOOL mask,
    OUT ULONG *localPort
    )
{
    EVTCHN_BIND_UNBOUND_PORT_IN in;
    EVTCHN_BIND_UNBOUND_PORT_OUT out;
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    in.RemoteDomain = remoteDomain;
    in.Event = event;
    in.Mask = !!mask;

    Log(XLL_DEBUG, L"RemoteDomain: %d, Event: 0x%x, Mask: %d", remoteDomain, event, mask);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND_PORT,
                              &in, sizeof(in),
                              &out, sizeof(out),
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND_PORT failed");
        goto fail;
    }

    *localPort = out.LocalPort;
    Log(XLL_DEBUG, L"LocalPort: %d", *localPort);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD EvtchnBindInterdomain(
    IN  HANDLE iface,
    IN  USHORT remoteDomain,
    IN  ULONG remotePort,
    IN  HANDLE event,
    IN  BOOL mask,
    OUT ULONG *localPort
    )
{
    EVTCHN_BIND_INTERDOMAIN_IN in;
    EVTCHN_BIND_INTERDOMAIN_OUT out;
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    in.RemoteDomain = remoteDomain;
    in.RemotePort = remotePort;
    in.Event = event;
    in.Mask = !!mask;

    Log(XLL_DEBUG, L"RemoteDomain: %d, RemotePort %d, Event: 0x%x, Mask: %d",
        remoteDomain, remotePort, event, mask);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN,
                              &in, sizeof(in),
                              &out, sizeof(out),
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN failed");
        goto fail;
    }

    *localPort = out.LocalPort;
    Log(XLL_DEBUG, L"LocalPort: %d", *localPort);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD EvtchnClose(
    IN  HANDLE iface,
    IN  ULONG localPort
    )
{
    EVTCHN_CLOSE_IN in;
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    in.LocalPort = localPort;

    Log(XLL_DEBUG, L"LocalPort: %d", localPort);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_EVTCHN_CLOSE,
                              &in, sizeof(in),
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_CLOSE failed");
        goto fail;
    }

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD EvtchnNotify(
    IN  HANDLE iface,
    IN  ULONG localPort
    )
{
    EVTCHN_NOTIFY_IN in;
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    in.LocalPort = localPort;

    Log(XLL_DEBUG, L"LocalPort: %d", localPort);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_EVTCHN_NOTIFY,
                              &in, sizeof(in),
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_NOTIFY failed");
        goto fail;
    }

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD EvtchnUnmask(
    IN  HANDLE iface,
    IN  ULONG localPort
    )
{
    EVTCHN_UNMASK_IN in;
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    in.LocalPort = localPort;

    Log(XLL_DEBUG, L"LocalPort: %d", localPort);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_EVTCHN_UNMASK,
                              &in, sizeof(in),
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_UNMASK failed");
        goto fail;
    }

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD GnttabGrantPages(
    IN  HANDLE iface,
    IN  USHORT remoteDomain,
    IN  ULONG numberPages,
    IN  ULONG notifyOffset,
    IN  ULONG notifyPort,
    IN  GNTTAB_GRANT_PAGES_FLAGS flags,
    OUT PVOID *address,
    OUT ULONG *references
    )
{
    GNTTAB_GRANT_PAGES_IN in1;
    GNTTAB_GET_GRANTS_IN in2;
    GNTTAB_GET_GRANTS_OUT *out2;
    PXENCONTROL_GNTTAB_REQUEST request;
    DWORD returned, size;
    BOOL success;
    DWORD status;

    FUNCTION_ENTER();

    in1.RequestId = g_RequestId;
    in1.RemoteDomain = remoteDomain;
    in1.NumberPages = numberPages;
    in1.NotifyOffset = notifyOffset;
    in1.NotifyPort = notifyPort;
    in1.Flags = flags;

    size = sizeof(GNTTAB_GET_GRANTS_OUT) + numberPages * sizeof(ULONG);
    out2 = malloc(size);
    request = malloc(sizeof(*request));

    status = ERROR_OUTOFMEMORY;
    if (!request || !out2)
        goto fail;

    ZeroMemory(request, sizeof(*request));
    request->Id = in1.RequestId;
    //request->Overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    Log(XLL_DEBUG, L"Id %lu, RemoteDomain: %d, NumberPages: %lu, NotifyOffset: 0x%x, NotifyPort: %lu, Flags: 0x%x",
        in1.RequestId, remoteDomain, numberPages, notifyOffset, notifyPort, flags);

    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_GRANT_PAGES,
                              &in1, sizeof(in1),
                              NULL, 0,
                              &returned,
                              &request->Overlapped);

    status = GetLastError();
    // this IOCTL is expected to be pending on success
    if (!success)
    {
        if (status != ERROR_IO_PENDING)
        {
            Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_GRANT_PAGES failed");
            goto fail;
        }
    }
    else
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_GRANT_PAGES not pending");
        status = ERROR_UNIDENTIFIED_ERROR;
        goto fail;
    }

    // get actual result
    in2.RequestId = in1.RequestId;
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_GET_GRANTS,
                              &in2, sizeof(in2),
                              out2, size,
                              &returned,
                              NULL);

    status = GetLastError();
    // FIXME: error handling
    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_GET_GRANTS failed");
        goto fail;
    }

    request->Address = out2->Address;
    EnterCriticalSection(&g_RequestListLock);
    InsertTailList(&g_RequestList, &request->ListEntry);
    g_RequestId++; // FIXME: synchronization
    LeaveCriticalSection(&g_RequestListLock);

    *address = out2->Address;
    memcpy(references, &out2->References, numberPages * sizeof(ULONG));
    Log(XLL_DEBUG, L"Address: 0x%p", *address);
    for (ULONG i = 0; i < numberPages; i++)
        Log(XLL_DEBUG, L"Grant ref[%lu]: %lu", i, out2->References[i]);

    free(out2);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", status, status);
    free(out2);
    free(request);
    FUNCTION_EXIT();
    return status;
}

DWORD GnttabUngrantPages(
    IN  HANDLE iface,
    IN  PVOID address
    )
{
    GNTTAB_UNGRANT_PAGES_IN in;
    PXENCONTROL_GNTTAB_REQUEST request;
    DWORD returned;
    BOOL success;
    DWORD status;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Address: 0x%p", address);

    status = ERROR_NOT_FOUND;
    request = FindRequest(address);
    if (!request)
    {
        Log(XLL_ERROR, L"Address %p not granted", address);
        goto fail;
    }

    in.RequestId = request->Id;

    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_UNGRANT_PAGES,
                              &in, sizeof(in),
                              NULL, 0,
                              &returned,
                              NULL);

    status = GetLastError();
    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_UNGRANT_PAGES failed");
        goto fail;
    }

    EnterCriticalSection(&g_RequestListLock);
    RemoveEntryList(&request->ListEntry);
    LeaveCriticalSection(&g_RequestListLock);
    free(request);

    FUNCTION_EXIT();
    return status;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", status, status);
    FUNCTION_EXIT();
    return status;
}

DWORD GnttabMapForeignPages(
    IN  HANDLE iface,
    IN  USHORT remoteDomain,
    IN  ULONG numberPages,
    IN  PULONG references,
    IN  ULONG notifyOffset,
    IN  ULONG notifyPort,
    IN  GNTTAB_GRANT_PAGES_FLAGS flags,
    OUT PVOID *address
    )
{
    GNTTAB_MAP_FOREIGN_PAGES_IN *in1;
    GNTTAB_GET_MAP_IN in2;
    GNTTAB_GET_MAP_OUT out2;
    PXENCONTROL_GNTTAB_REQUEST request;
    DWORD returned, size;
    BOOL success;
    DWORD status;

    FUNCTION_ENTER();

    status = ERROR_OUTOFMEMORY;
    size = sizeof(GNTTAB_MAP_FOREIGN_PAGES_IN) + numberPages * sizeof(ULONG);
    in1 = malloc(size);
    request = malloc(sizeof(*request));
    if (!in1 || !request)
        goto fail;

    in1->RequestId = g_RequestId;
    in1->RemoteDomain = remoteDomain;
    in1->NumberPages = numberPages;
    in1->NotifyOffset = notifyOffset;
    in1->NotifyPort = notifyPort;
    in1->Flags = flags;
    memcpy(&in1->References, references, numberPages * sizeof(ULONG));

    ZeroMemory(request, sizeof(*request));
    request->Id = in1->RequestId;
    //request->Overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    Log(XLL_DEBUG, L"Id %lu, RemoteDomain: %d, NumberPages: %d, NotifyOffset: 0x%x, NotifyPort: %d, Flags: 0x%x",
        in1->RequestId, remoteDomain, numberPages, notifyOffset, notifyPort, flags);

    for (ULONG i = 0; i < numberPages; i++)
        Log(XLL_DEBUG, L"Grant ref[%lu]: %lu", i, references[i]);

    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES,
                              in1, size,
                              NULL, 0,
                              &returned,
                              &request->Overlapped);

    status = GetLastError();
    // this IOCTL is expected to be pending on success
    if (!success)
    {
        if (status != ERROR_IO_PENDING)
        {
            Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES failed");
            goto fail;
        }
    }
    else
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES not pending");
        status = ERROR_UNIDENTIFIED_ERROR;
        goto fail;
    }

    // get actual result
    in2.RequestId = in1->RequestId;
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_GET_MAP,
                              &in2, sizeof(in2),
                              &out2, sizeof(out2),
                              &returned,
                              NULL);

    status = GetLastError();
    // FIXME: error handling
    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_GET_MAP failed");
        goto fail;
    }

    request->Address = out2.Address;
    EnterCriticalSection(&g_RequestListLock);
    InsertTailList(&g_RequestList, &request->ListEntry);
    g_RequestId++; // FIXME: synchronization
    LeaveCriticalSection(&g_RequestListLock);

    *address = out2.Address;

    Log(XLL_DEBUG, L"Address: 0x%p", *address);

    free(in1);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", status, status);
    free(in1);
    free(request);
    FUNCTION_EXIT();
    return status;
}

DWORD GnttabUnmapForeignPages(
    IN  HANDLE iface,
    IN  PVOID address
    )
{
    GNTTAB_UNMAP_FOREIGN_PAGES_IN in;
    PXENCONTROL_GNTTAB_REQUEST request;
    DWORD returned;
    BOOL success;
    DWORD status;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Address: 0x%p", address);

    status = ERROR_NOT_FOUND;
    request = FindRequest(address);
    if (!request)
    {
        Log(XLL_ERROR, L"Address %p not mapped", address);
        goto fail;
    }

    in.RequestId = request->Id;

    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES,
                              &in, sizeof(in),
                              NULL, 0,
                              &returned,
                              NULL);

    status = GetLastError();
    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES failed");
        goto fail;
    }

    EnterCriticalSection(&g_RequestListLock);
    RemoveEntryList(&request->ListEntry);
    LeaveCriticalSection(&g_RequestListLock);
    free(request);

    FUNCTION_EXIT();
    return status;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", status, status);
    FUNCTION_EXIT();
    return status;
}

DWORD StoreRead(
    IN  HANDLE iface,
    IN  PCHAR path,
    IN  DWORD cbOutput,
    OUT CHAR *output
    )
{
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S'", path);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_READ,
                              path, (DWORD)strlen(path) + 1,
                              output, cbOutput,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_READ failed");
        goto fail;
    }

    Log(XLL_DEBUG, L"Value: '%S'", output);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD StoreWrite(
    IN  HANDLE iface,
    IN  PCHAR path,
    IN  PCHAR value
    )
{
    PCHAR buffer;
    DWORD cbBuffer;
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    cbBuffer = (DWORD)(strlen(path) + 1 + strlen(value) + 1 + 1);
    buffer = malloc(cbBuffer);
    if (!buffer)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    ZeroMemory(buffer, cbBuffer);
    memcpy(buffer, path, strlen(path));
    memcpy(buffer + strlen(path) + 1, value, strlen(value));

    Log(XLL_DEBUG, L"Path: '%S', Value: '%S'", path, value);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_WRITE,
                              buffer, cbBuffer,
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_WRITE failed");
        goto fail;
    }

    free(buffer);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    free(buffer);
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD StoreDirectory(
    IN  HANDLE iface,
    IN  PCHAR path,
    IN  DWORD cbOutput,
    OUT CHAR *output
    )
{
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S'", path);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_DIRECTORY,
                              path, (DWORD)strlen(path) + 1,
                              output, cbOutput,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_DIRECTORY failed");
        goto fail;
    }

    LogMultiSz(__FUNCTION__, XLL_DEBUG, output);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD StoreRemove(
    IN  HANDLE iface,
    IN  PCHAR path
    )
{
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S'", path);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_REMOVE,
                              path, (DWORD)strlen(path) + 1,
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_REMOVE failed");
        goto fail;
    }

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD StoreSetPermissions(
    IN  HANDLE iface,
    IN  PCHAR path,
    IN  ULONG count,
    IN  PXENBUS_STORE_PERMISSION permissions
    )
{
    DWORD returned, size, i;
    BOOL success;
    STORE_SET_PERMISSIONS_IN *in1 = NULL;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S', count: %lu", path, count);
    for (i = 0; i < count; i++)
        Log(XLL_DEBUG, L"Domain: %d, Mask: 0x%x", permissions[i].Domain, permissions[i].Mask);

    size = sizeof(STORE_SET_PERMISSIONS_IN) + count * sizeof(XENBUS_STORE_PERMISSION);
    in1 = malloc(size);
    if (!in1)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    in1->Path = path;
    in1->PathLength = (DWORD)strlen(in1->Path) + 1;
    in1->NumberPermissions = count;
    memcpy(&in1->Permissions, permissions, count * sizeof(XENBUS_STORE_PERMISSION));

    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_SET_PERMISSIONS,
                              in1, size,
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_SET_PERMISSIONS failed");
        goto fail;
    }

    free(in1);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    free(in1);
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD StoreAddWatch(
    IN  HANDLE iface,
    IN  PCHAR path,
    IN  HANDLE event,
    OUT PVOID *handle
    )
{
    DWORD returned;
    BOOL success;
    STORE_ADD_WATCH_IN in1;
    STORE_ADD_WATCH_OUT out;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S', Event: 0x%x", path, event);

    in1.Path = path;
    in1.PathLength = (DWORD)strlen(path) + 1;
    in1.Event = event;
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_ADD_WATCH,
                              &in1, sizeof(in1),
                              &out, sizeof(out),
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_ADD_WATCH failed");
        goto fail;
    }

    *handle = out.Context;

    Log(XLL_DEBUG, L"Handle: %p", *handle);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD StoreRemoveWatch(
    IN  HANDLE iface,
    IN  PVOID handle
    )
{
    DWORD returned;
    BOOL success;
    STORE_REMOVE_WATCH_IN in1;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Handle: %p", handle);

    in1.Context = handle;
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_REMOVE_WATCH,
                              &in1, sizeof(in1),
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_REMOVE_WATCH failed");
        goto fail;
    }

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}
