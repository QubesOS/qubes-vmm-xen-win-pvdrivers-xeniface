#define INITGUID
#include "xenctrl_native.h"

#include <stdlib.h>
#include <winioctl.h>
#include <setupapi.h>

static XenifaceLogger *g_Logger = NULL;
static XENIFACE_LOG_LEVEL g_LogLevel = XLL_INFO;

#define Log(level, format, ...) _Log(level, __FUNCTION__, format, __VA_ARGS__)

#if defined (_DEBUG) || defined(DEBUG) || defined(DBG)
#   define FUNCTION_ENTER() _Log(XLL_TRACE, __FUNCTION__, L"-->")
#   define FUNCTION_EXIT() _Log(XLL_TRACE, __FUNCTION__, L"<--")
#else
#   define FUNCTION_ENTER()
#   define FUNCTION_EXIT()
#endif

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
                        FILE_ATTRIBUTE_NORMAL,
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
    Log(XLL_DEBUG, L"LocalPort: %d", localPort);

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
    Log(XLL_DEBUG, L"LocalPort: %d", localPort);

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
    OUT PVOID *handle,
    OUT PVOID *address,
    OUT ULONG *references
    )
{
    GNTTAB_GRANT_PAGES_IN in;
    GNTTAB_GRANT_PAGES_OUT *out;
    DWORD returned, size;
    BOOL success;

    FUNCTION_ENTER();

    in.RemoteDomain = remoteDomain;
    in.NumberPages = numberPages;
    in.NotifyOffset = notifyOffset;
    in.NotifyPort = notifyPort;
    in.Flags = flags;

    size = sizeof(GNTTAB_GRANT_PAGES_OUT) + numberPages * sizeof(ULONG);
    out = malloc(size);
    if (!out)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    Log(XLL_DEBUG, L"RemoteDomain: %d, NumberPages: %d, NotifyOffset: 0x%x, NotifyPort: %d, Flags: 0x%x",
        remoteDomain, numberPages, notifyOffset, notifyPort, flags);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_GRANT_PAGES,
                              &in, sizeof(in),
                              out, size,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_GRANT_PAGES failed");
        goto fail;
    }

    *address = out->Address;
    *handle = out->Context;
    memcpy(references, &out->References, numberPages * sizeof(ULONG));
    Log(XLL_DEBUG, L"Address: 0x%p, Context: 0x%p", *address, *handle);

    free(out);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    free(out);
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD GnttabUngrantPages(
    IN  HANDLE iface,
    IN  PVOID handle
    )
{
    GNTTAB_UNGRANT_PAGES_IN in;
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    in.Context = handle;

    Log(XLL_DEBUG, L"Context: 0x%p", handle);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_UNGRANT_PAGES,
                              &in, sizeof(in),
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_UNGRANT_PAGES failed");
        goto fail;
    }

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD GnttabMapForeignPages(
    IN  HANDLE iface,
    IN  USHORT remoteDomain,
    IN  ULONG numberPages,
    IN  PULONG references,
    IN  ULONG notifyOffset,
    IN  ULONG notifyPort,
    IN  GNTTAB_GRANT_PAGES_FLAGS flags,
    OUT PVOID *handle,
    OUT PVOID *address
    )
{
    GNTTAB_MAP_FOREIGN_PAGES_IN *in;
    GNTTAB_MAP_FOREIGN_PAGES_OUT out;
    DWORD returned, size;
    BOOL success;

    FUNCTION_ENTER();

    size = sizeof(GNTTAB_MAP_FOREIGN_PAGES_IN) + numberPages * sizeof(ULONG);
    in = malloc(size);
    if (!in)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    in->RemoteDomain = remoteDomain;
    in->NumberPages = numberPages;
    in->NotifyOffset = notifyOffset;
    in->NotifyPort = notifyPort;
    in->Flags = flags;
    memcpy(&in->References, references, numberPages * sizeof(ULONG));
    
    Log(XLL_DEBUG, L"RemoteDomain: %d, NumberPages: %d, NotifyOffset: 0x%x, NotifyPort: %d, Flags: 0x%x",
        remoteDomain, numberPages, notifyOffset, notifyPort, flags);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES,
                              in, size,
                              &out, sizeof(out),
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES failed");
        goto fail;
    }

    *address = out.Address;
    *handle = out.Context;
    Log(XLL_DEBUG, L"Address: 0x%p, Context: 0x%p", *address, *handle);

    free(in);
    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    free(in);
    FUNCTION_EXIT();
    return GetLastError();
}

DWORD GnttabUnmapForeignPages(
    IN  HANDLE iface,
    IN  PVOID handle
    )
{
    GNTTAB_UNMAP_FOREIGN_PAGES_IN in;
    DWORD returned;
    BOOL success;

    FUNCTION_ENTER();

    in.Context = handle;

    Log(XLL_DEBUG, L"Context: 0x%p", handle);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES,
                              &in, sizeof(in),
                              NULL, 0,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES failed");
        goto fail;
    }

    FUNCTION_EXIT();
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", GetLastError(), GetLastError());
    FUNCTION_EXIT();
    return GetLastError();
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

    Log(XLL_DEBUG, L"Path: '%S', Output: 0x%p, cbOutput: %lu 0x%lx", path, output, cbOutput, cbOutput);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_READ,
                              path, strlen(path) + 1,
                              output, cbOutput,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_READ failed");
        goto fail;
    }

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

    cbBuffer = strlen(path) + 1 + strlen(value) + 1 + 1;
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

    Log(XLL_DEBUG, L"Path: '%S', Output: 0x%p, cbOutput: %lu 0x%lx", path, output, cbOutput, cbOutput);
    success = DeviceIoControl(iface,
                              IOCTL_XENIFACE_STORE_DIRECTORY,
                              path, strlen(path) + 1,
                              output, cbOutput,
                              &returned,
                              NULL);

    if (!success)
    {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_DIRECTORY failed");
        goto fail;
    }

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
                              path, strlen(path) + 1,
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
