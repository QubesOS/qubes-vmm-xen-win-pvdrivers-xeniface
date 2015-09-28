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

struct _XENCONTROL_CONTEXT;
typedef struct _XENCONTROL_CONTEXT *PXENCONTROL_CONTEXT;

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
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XencontrolLogger *Logger
    );

XENCONTROL_API
void
XencontrolSetLogLevel(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XENCONTROL_LOG_LEVEL LogLevel
    );

XENCONTROL_API
DWORD
XencontrolOpen(
    IN  XencontrolLogger *Logger,
    OUT PXENCONTROL_CONTEXT *Xc
    );

XENCONTROL_API
void
XencontrolClose(
    IN  PXENCONTROL_CONTEXT Xc
    );

XENCONTROL_API
DWORD
EvtchnBindUnboundPort(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    );

XENCONTROL_API
DWORD
EvtchnBindInterdomain(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG RemotePort,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    );

XENCONTROL_API
DWORD
EvtchnClose(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
EvtchnNotify(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
EvtchnUnmask(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
GnttabGrantPages(
    IN  PXENCONTROL_CONTEXT Xc,
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
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    );

XENCONTROL_API
DWORD
GnttabMapForeignPages(
    IN  PXENCONTROL_CONTEXT Xc,
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
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    );

XENCONTROL_API
DWORD
StoreRead(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    );

XENCONTROL_API
DWORD
StoreWrite(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  PCHAR Value
    );

XENCONTROL_API
DWORD
StoreDirectory(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    );

XENCONTROL_API
DWORD
StoreRemove(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path
    );

XENCONTROL_API
DWORD
StoreSetPermissions(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  ULONG Count,
    IN  PXENBUS_STORE_PERMISSION Permissions
    );

XENCONTROL_API
DWORD
StoreAddWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  HANDLE Event,
    OUT PVOID *Handle
    );

XENCONTROL_API
DWORD
StoreRemoveWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Handle
    );

#ifdef __cplusplus
}
#endif

#endif // _XENCONTROL_H_
