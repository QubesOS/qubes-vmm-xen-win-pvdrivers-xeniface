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

typedef enum
_XENCONTROL_LOG_LEVEL {
    XLL_ERROR = 1,
    XLL_WARNING,
    XLL_INFO,
    XLL_DEBUG,
    XLL_TRACE,
} XENCONTROL_LOG_LEVEL;

typedef void
XencontrolLogger(
    IN XENCONTROL_LOG_LEVEL LogLevel,
    IN const CHAR *Function,
    IN const WCHAR *Format,
    IN va_list Args
    );

XENCONTROL_API
void
XcRegisterLogger(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XencontrolLogger *Logger
    );

XENCONTROL_API
void
XcSetLogLevel(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XENCONTROL_LOG_LEVEL LogLevel
    );

XENCONTROL_API
DWORD
XcOpen(
    IN  XencontrolLogger *Logger,
    OUT PXENCONTROL_CONTEXT *Xc
    );

XENCONTROL_API
void
XcClose(
    IN  PXENCONTROL_CONTEXT Xc
    );

XENCONTROL_API
DWORD
XcEvtchnBindUnbound(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    );

XENCONTROL_API
DWORD
XcEvtchnBindInterdomain(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG RemotePort,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    );

XENCONTROL_API
DWORD
XcEvtchnClose(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
XcEvtchnNotify(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
XcEvtchnUnmask(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

XENCONTROL_API
DWORD
XcGnttabPermitForeignAccess(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  XENIFACE_GNTTAB_PAGE_FLAGS Flags,
    OUT PVOID *Address,
    OUT ULONG *References
    );

XENCONTROL_API
DWORD
XcGnttabRevokeForeignAccess(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    );

XENCONTROL_API
DWORD
XcGnttabMapForeignPages(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  PULONG References,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  XENIFACE_GNTTAB_PAGE_FLAGS Flags,
    OUT PVOID *Address
    );

XENCONTROL_API
DWORD
XcGnttabUnmapForeignPages(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    );

XENCONTROL_API
DWORD
XcStoreRead(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    );

XENCONTROL_API
DWORD
XcStoreWrite(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  PCHAR Value
    );

XENCONTROL_API
DWORD
XcStoreDirectory(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    );

XENCONTROL_API
DWORD
XcStoreRemove(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path
    );

XENCONTROL_API
DWORD
XcStoreSetPermissions(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  ULONG Count,
    IN  PXENBUS_STORE_PERMISSION Permissions
    );

XENCONTROL_API
DWORD
XcStoreAddWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  HANDLE Event,
    OUT PVOID *Handle
    );

XENCONTROL_API
DWORD
XcStoreRemoveWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Handle
    );

#ifdef __cplusplus
}
#endif

#endif // _XENCONTROL_H_
