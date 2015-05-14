#pragma once
#include <windows.h>
#include <varargs.h>
#include "xeniface_ioctls.h"

#ifdef XENCONTROL_EXPORTS
#    define XENCONTROL_API __declspec(dllexport)
#else
#    define XENCONTROL_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _XENIFACE_LOG_LEVEL
{
    XLL_ERROR = 1,
    XLL_WARNING,
    XLL_INFO,
    XLL_DEBUG,
    XLL_TRACE,
} XENIFACE_LOG_LEVEL;

typedef void XenifaceLogger(IN XENIFACE_LOG_LEVEL logLevel, IN const PCHAR function, IN const PWCHAR format, IN va_list args);

XENCONTROL_API
void XenifaceRegisterLogger(
    IN  XenifaceLogger *logger
    );

XENCONTROL_API
void XenifaceSetLogLevel(
    IN  XENIFACE_LOG_LEVEL logLevel
    );
    
XENCONTROL_API
DWORD XenifaceOpen(
    OUT HANDLE *iface
    );

XENCONTROL_API
void XenifaceClose(
    IN  HANDLE xenIface
    );

XENCONTROL_API
DWORD EvtchnBindUnboundPort(
    IN  HANDLE iface,
    IN  USHORT remoteDomain,
    IN  HANDLE event,
    IN  BOOL mask,
    OUT ULONG *localPort
    );

XENCONTROL_API
DWORD EvtchnBindInterdomain(
    IN  HANDLE iface,
    IN  USHORT remoteDomain,
    IN  ULONG remotePort,
    IN  HANDLE event,
    IN  BOOL mask,
    OUT ULONG *localPort
    );

XENCONTROL_API
DWORD EvtchnClose(
    IN  HANDLE iface,
    IN  ULONG localPort
    );

XENCONTROL_API
DWORD EvtchnNotify(
    IN  HANDLE iface,
    IN  ULONG localPort
    );

XENCONTROL_API
DWORD EvtchnUnmask(
    IN  HANDLE iface,
    IN  ULONG localPort
    );

XENCONTROL_API
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
    );

XENCONTROL_API
DWORD GnttabUngrantPages(
    IN  HANDLE iface,
    IN  PVOID handle
    );

XENCONTROL_API
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
    );

XENCONTROL_API
DWORD GnttabUnmapForeignPages(
    IN  HANDLE iface,
    IN  PVOID handle
    );

XENCONTROL_API
DWORD StoreRead(
    IN  HANDLE iface,
    IN  PCHAR path,
    IN  DWORD cbOutput,
    OUT CHAR *output
    );

XENCONTROL_API
DWORD StoreWrite(
    IN  HANDLE iface,
    IN  PCHAR path,
    IN  PCHAR value
    );

XENCONTROL_API
DWORD StoreDirectory(
    IN  HANDLE iface,
    IN  PCHAR path,
    IN  DWORD cbOutput,
    OUT CHAR *output
    );

XENCONTROL_API
DWORD StoreRemove(
    IN  HANDLE iface,
    IN  PCHAR path
    );

#ifdef __cplusplus
}
#endif
