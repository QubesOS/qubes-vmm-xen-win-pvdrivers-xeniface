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

#ifndef _IOCTLS_H_
#define _IOCTLS_H_

#include "xeniface_ioctls.h"

typedef struct _XENIFACE_EVTCHN_CONTEXT {
    LIST_ENTRY Entry;
    PXENBUS_EVTCHN_CHANNEL Channel;
    ULONG LocalPort;
    PKEVENT Event;
    PEPROCESS Process;
    KDPC Dpc;
} XENIFACE_EVTCHN_CONTEXT, *PXENIFACE_EVTCHN_CONTEXT;

typedef struct _XENIFACE_GNTTAB_CONTEXT {
    LIST_ENTRY Entry;
    PXENBUS_GNTTAB_ENTRY *Grants;
    PEPROCESS Process;
    USHORT RemoteDomain;
    ULONG NumberPages;
    GNTTAB_GRANT_PAGES_FLAGS Flags;
    ULONG NotifyOffset;
    ULONG NotifyPort;
    PVOID KernelVa;
    PVOID UserVa;
    PMDL Mdl;
} XENIFACE_GNTTAB_CONTEXT, *PXENIFACE_GNTTAB_CONTEXT;

NTSTATUS
XenIFaceIoctl(
    __in  PXENIFACE_FDO     Fdo,
    __in  PIRP              Irp
    );

VOID
XenifaceProcessNotify(
    __in HANDLE ParentId,
    __in HANDLE ProcessId,
    __in BOOLEAN Create
    );

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
GnttabAcquireLock(
    __in PVOID Argument
    );

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
GnttabReleaseLock(
    __in PVOID Argument
    );

#endif // _IOCTLS_H_
