/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _XENIFACE_IOCTLS_H_
#define _XENIFACE_IOCTLS_H_

DEFINE_GUID(GUID_INTERFACE_XENIFACE, \
            0xb2cfb085, 0xaa5e, 0x47e1, 0x8b, 0xf7, 0x97, 0x93, 0xf3, 0x15, 0x45, 0x65);

/************************************************************************/
/* store ioctls                                                         */
/************************************************************************/
// define only for user mode clients
#ifndef XENIFACE_KERNEL_MODE

typedef enum _XENBUS_STORE_PERMISSION_MASK {
    XS_PERM_NONE = 0,
    XS_PERM_READ = 1,
    XS_PERM_WRITE = 2,
} XENBUS_STORE_PERMISSION_MASK;

typedef struct _XENBUS_STORE_PERMISSION {
    USHORT Domain;
    XENBUS_STORE_PERMISSION_MASK Mask;
} XENBUS_STORE_PERMISSION, *PXENBUS_STORE_PERMISSION;

#endif

#define XENBUS_STORE_ALLOWED_PERMISSIONS  (XS_PERM_NONE | XS_PERM_READ | XS_PERM_WRITE)

#define IOCTL_XENIFACE_STORE_READ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XENIFACE_STORE_WRITE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XENIFACE_STORE_DIRECTORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XENIFACE_STORE_REMOVE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XENIFACE_STORE_SET_PERMISSIONS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma warning(push)
#pragma warning(disable:4200) // nonstandard extension used : zero-sized array in struct/union
typedef struct _STORE_SET_PERMISSIONS_IN
{
    PCHAR Path;
    ULONG PathLength; // number of bytes, including the null terminator
    ULONG NumberPermissions;
    XENBUS_STORE_PERMISSION Permissions[0];
} STORE_SET_PERMISSIONS_IN, *PSTORE_SET_PERMISSIONS_IN;
#pragma warning(pop)

#define IOCTL_XENIFACE_STORE_ADD_WATCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _STORE_ADD_WATCH_IN
{
    PCHAR Path;
    ULONG PathLength; // number of bytes, including the null terminator
    HANDLE Event;
} STORE_ADD_WATCH_IN, *PSTORE_ADD_WATCH_IN;

typedef struct _STORE_ADD_WATCH_OUT
{
    PVOID Context;
} STORE_ADD_WATCH_OUT, *PSTORE_ADD_WATCH_OUT;

#define IOCTL_XENIFACE_STORE_REMOVE_WATCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _STORE_REMOVE_WATCH_IN
{
    PVOID Context;
} STORE_REMOVE_WATCH_IN, *PSTORE_REMOVE_WATCH_IN;

/************************************************************************/
/* evtchn ioctls                                                        */
/************************************************************************/
#define IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EVTCHN_BIND_INTERDOMAIN_IN
{
    USHORT RemoteDomain;
    ULONG RemotePort;
    BOOLEAN Mask;
    HANDLE Event;
} EVTCHN_BIND_INTERDOMAIN_IN, *PEVTCHN_BIND_INTERDOMAIN_IN;

typedef struct _EVTCHN_BIND_INTERDOMAIN_OUT
{
    ULONG LocalPort;
} EVTCHN_BIND_INTERDOMAIN_OUT, *PEVTCHN_BIND_INTERDOMAIN_OUT;

#define IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND_PORT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EVTCHN_BIND_UNBOUND_PORT_IN
{
    USHORT RemoteDomain;
    BOOLEAN Mask;
    HANDLE Event;
} EVTCHN_BIND_UNBOUND_PORT_IN, *PEVTCHN_BIND_UNBOUND_PORT_IN;

typedef struct _EVTCHN_BIND_UNBOUND_PORT_OUT
{
    ULONG LocalPort;
} EVTCHN_BIND_UNBOUND_PORT_OUT, *PEVTCHN_BIND_UNBOUND_PORT_OUT;

#define IOCTL_XENIFACE_EVTCHN_CLOSE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EVTCHN_CLOSE_IN
{
    ULONG LocalPort;
} EVTCHN_CLOSE_IN, *PEVTCHN_CLOSE_IN;

#define IOCTL_XENIFACE_EVTCHN_NOTIFY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EVTCHN_NOTIFY_IN
{
    ULONG LocalPort;
} EVTCHN_NOTIFY_IN, *PEVTCHN_NOTIFY_IN;

#define IOCTL_XENIFACE_EVTCHN_UNMASK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EVTCHN_UNMASK_IN
{
    ULONG LocalPort;
} EVTCHN_UNMASK_IN, *PEVTCHN_UNMASK_IN;

#define IOCTL_XENIFACE_EVTCHN_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EVTCHN_STATUS_IN
{
    ULONG LocalPort;
} EVTCHN_STATUS_IN, *PEVTCHN_STATUS_IN;

typedef struct _EVTCHN_STATUS_OUT
{
    ULONG Status;
} EVTCHN_STATUS_OUT, *PEVTCHN_STATUS_OUT;

/************************************************************************/
/* gntmem ioctls                                                        */
/************************************************************************/
#define IOCTL_XENIFACE_GNTTAB_GRANT_PAGES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _GNTTAB_GRANT_PAGES_FLAGS
{
    GNTTAB_GRANT_PAGES_READONLY          = 1 << 0,
    GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET = 1 << 1,
    GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT   = 1 << 2,
} GNTTAB_GRANT_PAGES_FLAGS;

typedef struct _GNTTAB_GRANT_PAGES_IN
{
    USHORT RemoteDomain;
    ULONG NumberPages;
    GNTTAB_GRANT_PAGES_FLAGS Flags;
    ULONG NotifyOffset;
    ULONG NotifyPort;
} GNTTAB_GRANT_PAGES_IN, *PGNTTAB_GRANT_PAGES_IN;

#pragma warning(push)
#pragma warning(disable:4200) // nonstandard extension used : zero-sized array in struct/union
typedef struct _GNTTAB_GRANT_PAGES_OUT
{
    PVOID Address;
    PVOID Context;
    ULONG References[0];
} GNTTAB_GRANT_PAGES_OUT, *PGNTTAB_GRANT_PAGES_OUT;
#pragma warning(pop)

#define IOCTL_XENIFACE_GNTTAB_UNGRANT_PAGES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _GNTTAB_UNGRANT_PAGES_IN
{
    PVOID Context;
} GNTTAB_UNGRANT_PAGES_IN, *PGNTTAB_UNGRANT_PAGES_IN;

#define IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma warning(push)
#pragma warning(disable:4200) // nonstandard extension used : zero-sized array in struct/union
typedef struct _GNTTAB_MAP_FOREIGN_PAGES_IN
{
    USHORT RemoteDomain;
    ULONG NumberPages;
    GNTTAB_GRANT_PAGES_FLAGS Flags;
    ULONG NotifyOffset;
    ULONG NotifyPort;
    ULONG References[0];
} GNTTAB_MAP_FOREIGN_PAGES_IN, *PGNTTAB_MAP_FOREIGN_PAGES_IN;
#pragma warning(pop)

typedef struct _GNTTAB_MAP_FOREIGN_PAGES_OUT
{
    PVOID Address;
    PVOID Context;
} GNTTAB_MAP_FOREIGN_PAGES_OUT, *PGNTTAB_MAP_FOREIGN_PAGES_OUT;

#define IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _GNTTAB_UNMAP_FOREIGN_PAGES_IN
{
    PVOID Context;
} GNTTAB_UNMAP_FOREIGN_PAGES_IN, *PGNTTAB_UNMAP_FOREIGN_PAGES_IN;

#endif // _XENIFACE_IOCTLS_H_
