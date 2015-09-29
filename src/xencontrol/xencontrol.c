#define INITGUID
#include <windows.h>
#include <setupapi.h>
#include <stdlib.h>
#include <assert.h>

#include "xencontrol.h"
#include "xencontrol_private.h"

BOOL APIENTRY
DllMain(
    IN  HMODULE Module,
    IN  DWORD ReasonForCall,
    IN  LPVOID Reserved
)
{
    return TRUE;
}

static void
_Log(
    IN  XencontrolLogger *Logger,
    IN  XENCONTROL_LOG_LEVEL LogLevel,
    IN  XENCONTROL_LOG_LEVEL CurrentLogLevel,
    IN  PCHAR Function,
    IN  PWCHAR Format,
    ...
    )
{
    va_list Args;
    DWORD LastError;

    if (!Logger)
        return;

    if (LogLevel > CurrentLogLevel)
        return;

    LastError = GetLastError();
    va_start(Args, Format);
    Logger(LogLevel, Function, Format, Args);
    va_end(Args);
    SetLastError(LastError);
}

static void
_LogMultiSz(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Caller,
    IN  XENCONTROL_LOG_LEVEL Level,
    IN  PCHAR MultiSz
    )
{
    PCHAR Ptr;
    ULONG Len;

    for (Ptr = MultiSz; *Ptr;)
    {
        Len = (ULONG)strlen(Ptr);
        _Log(Xc->Logger, Level, Xc->LogLevel, Caller, L"%S", Ptr);
        Ptr += (Len + 1);
    }
}

void
XcRegisterLogger(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XencontrolLogger *Logger
    )
{
    FUNCTION_ENTER();
    Xc->Logger = Logger;
    FUNCTION_EXIT();
}

void
XcSetLogLevel(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XENCONTROL_LOG_LEVEL LogLevel
    )
{
    Xc->LogLevel = LogLevel;
}

DWORD
XcOpen(
    IN  XencontrolLogger *Logger,
    OUT PXENCONTROL_CONTEXT *Xc
    )
{
    HDEVINFO DevInfo;
    SP_DEVICE_INTERFACE_DATA InterfaceData;
    SP_DEVICE_INTERFACE_DETAIL_DATA *DetailData = NULL;
    DWORD BufferSize;
    PXENCONTROL_CONTEXT Context;

    Context = malloc(sizeof(*Context));
    if (Context == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Context->Logger = Logger;
    Context->LogLevel = XLL_INFO;
    Context->RequestId = 1;
    InitializeListHead(&Context->RequestList);
    InitializeCriticalSection(&Context->RequestListLock);

    DevInfo = SetupDiGetClassDevs(&GUID_INTERFACE_XENIFACE, 0, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"XENIFACE device class doesn't exist");
        goto fail;
    }

    InterfaceData.cbSize = sizeof(InterfaceData);
    if (!SetupDiEnumDeviceInterfaces(DevInfo, NULL, &GUID_INTERFACE_XENIFACE, 0, &InterfaceData))
    {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to enumerate XENIFACE devices");
        goto fail;
    }

    SetupDiGetDeviceInterfaceDetail(DevInfo, &InterfaceData, NULL, 0, &BufferSize, NULL);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to get buffer size for device details");
        goto fail;
    }

    // Using 'BufferSize' from failed function call
    // ...yeah, that's the point
#pragma warning(suppress: 6102)
    DetailData = (SP_DEVICE_INTERFACE_DETAIL_DATA *)malloc(BufferSize);
    if (!DetailData)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    DetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

    if (!SetupDiGetDeviceInterfaceDetail(DevInfo, &InterfaceData, DetailData, BufferSize, NULL, NULL))
    {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to get XENIFACE device path");
        goto fail;
    }

    Context->XenIface = CreateFile(DetailData->DevicePath,
                                   FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                                   0,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                                   NULL);

    if (Context->XenIface == INVALID_HANDLE_VALUE)
    {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to open XENIFACE device, path: %s", DetailData->DevicePath);
        goto fail;
    }

    _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
         L"XenIface handle: 0x%x", Context->XenIface);

    free(DetailData);
    *Xc = Context;
    return ERROR_SUCCESS;

fail:
    _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
         L"Error: %d 0x%x", GetLastError(), GetLastError());
    free(DetailData);
    return GetLastError();
}

void
XcClose(
    IN  PXENCONTROL_CONTEXT Xc
    )
{
    FUNCTION_ENTER();
    CloseHandle(Xc->XenIface);
    DeleteCriticalSection(&Xc->RequestListLock);
    FUNCTION_EXIT();
    free(Xc);
}

DWORD
XcEvtchnBindUnbound(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    )
{
    EVTCHN_BIND_UNBOUND_PORT_IN In;
    EVTCHN_BIND_UNBOUND_PORT_OUT Out;
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    In.RemoteDomain = RemoteDomain;
    In.Event = Event;
    In.Mask = !!Mask;

    Log(XLL_DEBUG, L"RemoteDomain: %d, Event: 0x%x, Mask: %d", RemoteDomain, Event, Mask);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND_PORT,
                              &In, sizeof(In),
                              &Out, sizeof(Out),
                              &Returned,
                              NULL);

    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND_PORT failed");
        goto fail;
    }

    *LocalPort = Out.LocalPort;
    Log(XLL_DEBUG, L"LocalPort: %d", *LocalPort);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD
XcEvtchnBindInterdomain(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG RemotePort,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    )
{
    EVTCHN_BIND_INTERDOMAIN_IN In;
    EVTCHN_BIND_INTERDOMAIN_OUT Out;
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    In.RemoteDomain = RemoteDomain;
    In.RemotePort = RemotePort;
    In.Event = Event;
    In.Mask = !!Mask;

    Log(XLL_DEBUG, L"RemoteDomain: %d, RemotePort %d, Event: 0x%x, Mask: %d",
        RemoteDomain, RemotePort, Event, Mask);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN,
                              &In, sizeof(In),
                              &Out, sizeof(Out),
                              &Returned,
                              NULL);

    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN failed");
        goto fail;
    }

    *LocalPort = Out.LocalPort;
    Log(XLL_DEBUG, L"LocalPort: %d", *LocalPort);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD
XcEvtchnClose(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    )
{
    EVTCHN_CLOSE_IN In;
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %d", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_CLOSE,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success)
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

DWORD
XcEvtchnNotify(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    )
{
    EVTCHN_NOTIFY_IN In;
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %d", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_NOTIFY,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success)
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

DWORD
XcEvtchnUnmask(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    )
{
    EVTCHN_UNMASK_IN In;
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %d", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_UNMASK,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success)
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

static PXENCONTROL_GNTTAB_REQUEST
FindRequest(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    )
{
    PLIST_ENTRY Entry;
    PXENCONTROL_GNTTAB_REQUEST ReturnRequest = NULL;

    EnterCriticalSection(&Xc->RequestListLock);
    Entry = Xc->RequestList.Flink;
    while (Entry != &Xc->RequestList)
    {
        PXENCONTROL_GNTTAB_REQUEST Request = CONTAINING_RECORD(Entry, XENCONTROL_GNTTAB_REQUEST, ListEntry);
        if (Request->Address == Address)
        {
            ReturnRequest = Request;
            break;
        }

        Entry = Entry->Flink;
    }
    LeaveCriticalSection(&Xc->RequestListLock);

    return ReturnRequest;
}

DWORD
XcGnttabGrantAccess(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  GNTTAB_GRANT_PAGES_FLAGS Flags,
    OUT PVOID *Address,
    OUT ULONG *References
    )
{
    GNTTAB_GRANT_PAGES_IN In1;
    GNTTAB_GET_GRANTS_IN In2;
    GNTTAB_GET_GRANTS_OUT *Out2;
    PXENCONTROL_GNTTAB_REQUEST Request;
    DWORD Returned, Size;
    BOOL Success;
    DWORD Status;

    FUNCTION_ENTER();

    // lock the whole operation to not generate duplicate IDs
    EnterCriticalSection(&Xc->RequestListLock);

    In1.RequestId = Xc->RequestId;
    In1.RemoteDomain = RemoteDomain;
    In1.NumberPages = NumberPages;
    In1.NotifyOffset = NotifyOffset;
    In1.NotifyPort = NotifyPort;
    In1.Flags = Flags;

    Size = sizeof(GNTTAB_GET_GRANTS_OUT) + NumberPages * sizeof(ULONG);
    Out2 = malloc(Size);
    Request = malloc(sizeof(*Request));

    Status = ERROR_OUTOFMEMORY;
    if (!Request || !Out2)
        goto fail;

    ZeroMemory(Request, sizeof(*Request));
    Request->Id = In1.RequestId;
    //request->Overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    Log(XLL_DEBUG, L"Id %lu, RemoteDomain: %d, NumberPages: %lu, NotifyOffset: 0x%x, NotifyPort: %lu, Flags: 0x%x",
        In1.RequestId, RemoteDomain, NumberPages, NotifyOffset, NotifyPort, Flags);

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_GRANT_PAGES,
                              &In1, sizeof(In1),
                              NULL, 0,
                              &Returned,
                              &Request->Overlapped);

    Status = GetLastError();
    // this IOCTL is expected to be pending on success
    if (!Success)
    {
        if (Status != ERROR_IO_PENDING)
        {
            Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_GRANT_PAGES failed");
            goto fail;
        }
    }
    else
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_GRANT_PAGES not pending");
        Status = ERROR_UNIDENTIFIED_ERROR;
        goto fail;
    }

    // get actual result
    In2.RequestId = In1.RequestId;
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_GET_GRANTS,
                              &In2, sizeof(In2),
                              Out2, Size,
                              &Returned,
                              NULL);

    assert(Success);

    Request->Address = Out2->Address;

    InsertTailList(&Xc->RequestList, &Request->ListEntry);
    Xc->RequestId++;
    LeaveCriticalSection(&Xc->RequestListLock);

    *Address = Out2->Address;
    memcpy(References, &Out2->References, NumberPages * sizeof(ULONG));
    Log(XLL_DEBUG, L"Address: 0x%p", *Address);
    for (ULONG i = 0; i < NumberPages; i++)
        Log(XLL_DEBUG, L"Grant ref[%lu]: %lu", i, Out2->References[i]);

    free(Out2);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    LeaveCriticalSection(&Xc->RequestListLock);
    Log(XLL_ERROR, L"Error: %d 0x%x", Status, Status);
    free(Out2);
    free(Request);
    FUNCTION_EXIT();
    return Status;
}

DWORD
XcGnttabRevokeAccess(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    )
{
    GNTTAB_UNGRANT_PAGES_IN In;
    PXENCONTROL_GNTTAB_REQUEST Request;
    DWORD Returned;
    BOOL Success;
    DWORD Status;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Address: 0x%p", Address);

    Status = ERROR_NOT_FOUND;
    Request = FindRequest(Xc, Address);
    if (!Request)
    {
        Log(XLL_ERROR, L"Address %p not granted", Address);
        goto fail;
    }

    In.RequestId = Request->Id;

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_UNGRANT_PAGES,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    Status = GetLastError();
    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_UNGRANT_PAGES failed");
        goto fail;
    }

    EnterCriticalSection(&Xc->RequestListLock);
    RemoveEntryList(&Request->ListEntry);
    LeaveCriticalSection(&Xc->RequestListLock);
    free(Request);

    FUNCTION_EXIT();
    return Status;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", Status, Status);
    FUNCTION_EXIT();
    return Status;
}

DWORD
XcGnttabMap(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  PULONG References,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  GNTTAB_GRANT_PAGES_FLAGS Flags,
    OUT PVOID *Address
    )
{
    GNTTAB_MAP_FOREIGN_PAGES_IN *In1;
    GNTTAB_GET_MAP_IN In2;
    GNTTAB_GET_MAP_OUT Out2;
    PXENCONTROL_GNTTAB_REQUEST Request;
    DWORD Returned, Size;
    BOOL Success;
    DWORD Status;

    FUNCTION_ENTER();

    // lock the whole operation to not generate duplicate IDs
    EnterCriticalSection(&Xc->RequestListLock);

    Status = ERROR_OUTOFMEMORY;
    Size = sizeof(GNTTAB_MAP_FOREIGN_PAGES_IN) + NumberPages * sizeof(ULONG);
    In1 = malloc(Size);
    Request = malloc(sizeof(*Request));
    if (!In1 || !Request)
        goto fail;

    In1->RequestId = Xc->RequestId;
    In1->RemoteDomain = RemoteDomain;
    In1->NumberPages = NumberPages;
    In1->NotifyOffset = NotifyOffset;
    In1->NotifyPort = NotifyPort;
    In1->Flags = Flags;
    memcpy(&In1->References, References, NumberPages * sizeof(ULONG));

    ZeroMemory(Request, sizeof(*Request));
    Request->Id = In1->RequestId;
    //request->Overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    Log(XLL_DEBUG, L"Id %lu, RemoteDomain: %d, NumberPages: %d, NotifyOffset: 0x%x, NotifyPort: %d, Flags: 0x%x",
        In1->RequestId, RemoteDomain, NumberPages, NotifyOffset, NotifyPort, Flags);

    for (ULONG i = 0; i < NumberPages; i++)
        Log(XLL_DEBUG, L"Grant ref[%lu]: %lu", i, References[i]);

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES,
                              In1, Size,
                              NULL, 0,
                              &Returned,
                              &Request->Overlapped);

    Status = GetLastError();
    // this IOCTL is expected to be pending on success
    if (!Success)
    {
        if (Status != ERROR_IO_PENDING)
        {
            Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES failed");
            goto fail;
        }
    }
    else
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES not pending");
        Status = ERROR_UNIDENTIFIED_ERROR;
        goto fail;
    }

    // get actual result
    In2.RequestId = In1->RequestId;
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_GET_MAP,
                              &In2, sizeof(In2),
                              &Out2, sizeof(Out2),
                              &Returned,
                              NULL);

    assert(Success);

    Request->Address = Out2.Address;
    InsertTailList(&Xc->RequestList, &Request->ListEntry);
    Xc->RequestId++;
    LeaveCriticalSection(&Xc->RequestListLock);

    *Address = Out2.Address;

    Log(XLL_DEBUG, L"Address: 0x%p", *Address);

    free(In1);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    LeaveCriticalSection(&Xc->RequestListLock);
    Log(XLL_ERROR, L"Error: %d 0x%x", Status, Status);
    free(In1);
    free(Request);
    FUNCTION_EXIT();
    return Status;
}

DWORD
XcGnttabUnmap(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    )
{
    GNTTAB_UNMAP_FOREIGN_PAGES_IN In;
    PXENCONTROL_GNTTAB_REQUEST Request;
    DWORD Returned;
    BOOL Success;
    DWORD Status;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Address: 0x%p", Address);

    Status = ERROR_NOT_FOUND;
    Request = FindRequest(Xc, Address);
    if (!Request)
    {
        Log(XLL_ERROR, L"Address %p not mapped", Address);
        goto fail;
    }

    In.RequestId = Request->Id;

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    Status = GetLastError();
    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES failed");
        goto fail;
    }

    EnterCriticalSection(&Xc->RequestListLock);
    RemoveEntryList(&Request->ListEntry);
    LeaveCriticalSection(&Xc->RequestListLock);
    free(Request);

    FUNCTION_EXIT();
    return Status;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", Status, Status);
    FUNCTION_EXIT();
    return Status;
}

DWORD
XcStoreRead(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    )
{
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_READ,
                              Path, (DWORD)strlen(Path) + 1,
                              Output, cbOutput,
                              &Returned,
                              NULL);

    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_READ failed");
        goto fail;
    }

    Log(XLL_DEBUG, L"Value: '%S'", Output);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD
XcStoreWrite(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  PCHAR Value
    )
{
    PCHAR Buffer;
    DWORD cbBuffer;
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    cbBuffer = (DWORD)(strlen(Path) + 1 + strlen(Value) + 1 + 1);
    Buffer = malloc(cbBuffer);
    if (!Buffer)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    ZeroMemory(Buffer, cbBuffer);
    memcpy(Buffer, Path, strlen(Path));
    memcpy(Buffer + strlen(Path) + 1, Value, strlen(Value));

    Log(XLL_DEBUG, L"Path: '%S', Value: '%S'", Path, Value);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_WRITE,
                              Buffer, cbBuffer,
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_WRITE failed");
        goto fail;
    }

    free(Buffer);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    free(Buffer);
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD
XcStoreDirectory(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    )
{
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_DIRECTORY,
                              Path, (DWORD)strlen(Path) + 1,
                              Output, cbOutput,
                              &Returned,
                              NULL);

    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_DIRECTORY failed");
        goto fail;
    }

    _LogMultiSz(Xc, __FUNCTION__, XLL_DEBUG, Output);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD
XcStoreRemove(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path
    )
{
    DWORD Returned;
    BOOL Success;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_REMOVE,
                              Path, (DWORD)strlen(Path) + 1,
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success)
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

DWORD
XcStoreSetPermissions(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  ULONG Count,
    IN  PXENBUS_STORE_PERMISSION Permissions
    )
{
    DWORD Returned, Size;
    BOOL Success;
    STORE_SET_PERMISSIONS_IN *In = NULL;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S', count: %lu", Path, Count);
    for (ULONG i = 0; i < Count; i++)
        Log(XLL_DEBUG, L"Domain: %d, Mask: 0x%x", Permissions[i].Domain, Permissions[i].Mask);

    Size = sizeof(STORE_SET_PERMISSIONS_IN) + Count * sizeof(XENBUS_STORE_PERMISSION);
    In = malloc(Size);
    if (!In)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    In->Path = Path;
    In->PathLength = (DWORD)strlen(In->Path) + 1;
    In->NumberPermissions = Count;
    memcpy(&In->Permissions, Permissions, Count * sizeof(XENBUS_STORE_PERMISSION));

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_SET_PERMISSIONS,
                              In, Size,
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_SET_PERMISSIONS failed");
        goto fail;
    }

    free(In);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    free(In);
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD
XcStoreAddWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  HANDLE Event,
    OUT PVOID *Handle
    )
{
    DWORD Returned;
    BOOL Success;
    STORE_ADD_WATCH_IN In;
    STORE_ADD_WATCH_OUT Out;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Path: '%S', Event: 0x%x", Path, Event);

    In.Path = Path;
    In.PathLength = (DWORD)strlen(Path) + 1;
    In.Event = Event;
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_ADD_WATCH,
                              &In, sizeof(In),
                              &Out, sizeof(Out),
                              &Returned,
                              NULL);

    if (!Success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_ADD_WATCH failed");
        goto fail;
    }

    *Handle = Out.Context;

    Log(XLL_DEBUG, L"Handle: %p", *Handle);

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD
XcStoreRemoveWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Handle
    )
{
    DWORD Returned;
    BOOL Success;
    STORE_REMOVE_WATCH_IN In;

    FUNCTION_ENTER();

    Log(XLL_DEBUG, L"Handle: %p", Handle);

    In.Context = Handle;
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_REMOVE_WATCH,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success)
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
