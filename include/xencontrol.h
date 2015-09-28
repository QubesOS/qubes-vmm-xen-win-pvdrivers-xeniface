#ifndef _XENCONTROL_H_
#define _XENCONTROL_H_

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

typedef enum _XENCONTROL_LOG_LEVEL {
    XLL_ERROR = 1,
    XLL_WARNING,
    XLL_INFO,
    XLL_DEBUG,
    XLL_TRACE,
} XENCONTROL_LOG_LEVEL;

typedef void
XencontrolLogger(
    IN XENCONTROL_LOG_LEVEL LogLevel,
    IN const PCHAR Function,
    IN const PWCHAR Format,
    IN va_list Args
    );

XENCONTROL_API
void
XencontrolRegisterLogger(
    IN  XencontrolLogger *Logger
    );

XENCONTROL_API
void
XencontrolSetLogLevel(
    IN  XENCONTROL_LOG_LEVEL LogLevel
    );

XENCONTROL_API
DWORD
XencontrolOpen(
    OUT HANDLE *Iface
    );

XENCONTROL_API
void
XencontrolClose(
    IN  HANDLE Iface
    );

XENCONTROL_API
DWORD
EvtchnBindUnboundPort(
    IN  HANDLE Iface,
    IN  USHORT RemoteDomain,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    );

XENCONTROL_API
DWORD
EvtchnBindInterdomain(
    IN  HANDLE Iface,
    IN  USHORT RemoteDomain,
    IN  ULONG RemotePort,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    );

XENCONTROL_API
DWORD
EvtchnClose(
    IN  HANDLE Iface,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
EvtchnNotify(
    IN  HANDLE Iface,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
EvtchnUnmask(
    IN  HANDLE Iface,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
GnttabGrantPages(
    IN  HANDLE Iface,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  GNTTAB_GRANT_PAGES_FLAGS Flags,
    OUT PVOID *Address,
    OUT ULONG *References
    );

XENCONTROL_API
DWORD
GnttabUngrantPages(
    IN  HANDLE Iface,
    IN  PVOID Address
    );

XENCONTROL_API
DWORD
GnttabMapForeignPages(
    IN  HANDLE Iface,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  PULONG References,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  GNTTAB_GRANT_PAGES_FLAGS Flags,
    OUT PVOID *Address
    );

XENCONTROL_API
DWORD
GnttabUnmapForeignPages(
    IN  HANDLE Iface,
    IN  PVOID Address
    );

XENCONTROL_API
DWORD
StoreRead(
    IN  HANDLE Iface,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    );

XENCONTROL_API
DWORD
StoreWrite(
    IN  HANDLE Iface,
    IN  PCHAR Path,
    IN  PCHAR Value
    );

XENCONTROL_API
DWORD
StoreDirectory(
    IN  HANDLE Iface,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    );

XENCONTROL_API
DWORD
StoreRemove(
    IN  HANDLE Iface,
    IN  PCHAR Path
    );

XENCONTROL_API
DWORD
StoreSetPermissions(
    IN  HANDLE Iface,
    IN  PCHAR Path,
    IN  ULONG Count,
    IN  PXENBUS_STORE_PERMISSION Permissions
    );

XENCONTROL_API
DWORD
StoreAddWatch(
    IN  HANDLE Iface,
    IN  PCHAR Path,
    IN  HANDLE Event,
    OUT PVOID *Handle
    );

XENCONTROL_API
DWORD
StoreRemoveWatch(
    IN  HANDLE Iface,
    IN  PVOID Handle
    );

#ifdef __cplusplus
}
#endif

#endif // _XENCONTROL_H_
