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

#include "driver.h"
#include "ioctls.h"
#include "..\..\include\xeniface_ioctls.h"
#include "log.h"

// Cleanup store watches and event channels, called on file object close.
_IRQL_requires_(PASSIVE_LEVEL) // EvtchnFree calls KeFlushQueuedDpcs
VOID
XenIfaceCleanup(
    PXENIFACE_FDO Fdo,
    PFILE_OBJECT  FileObject
    )
{
    PLIST_ENTRY Node;
    PXENIFACE_STORE_CONTEXT StoreContext;
    PXENIFACE_EVTCHN_CONTEXT EvtchnContext;
    KIRQL Irql;
    LIST_ENTRY ToFree;

    XenIfaceDebugPrint(TRACE, "FO %p, IRQL %d, Cpu %lu\n", FileObject, KeGetCurrentIrql(), KeGetCurrentProcessorNumber());

    // store watches
    KeAcquireSpinLock(&Fdo->StoreWatchLock, &Irql);
    Node = Fdo->StoreWatchList.Flink;
    while (Node->Flink != Fdo->StoreWatchList.Flink) {
        StoreContext = CONTAINING_RECORD(Node, XENIFACE_STORE_CONTEXT, Entry);

        Node = Node->Flink;
        if (StoreContext->FileObject != FileObject)
            continue;

        XenIfaceDebugPrint(TRACE, "Store context %p\n", StoreContext);
        RemoveEntryList(&StoreContext->Entry);
        StoreFreeWatch(Fdo, StoreContext);
    }
    KeReleaseSpinLock(&Fdo->StoreWatchLock, Irql);

    // event channels
    InitializeListHead(&ToFree);
    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    Node = Fdo->EvtchnList.Flink;
    while (Node->Flink != Fdo->EvtchnList.Flink) {
        EvtchnContext = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);

        Node = Node->Flink;
        if (EvtchnContext->FileObject != FileObject)
            continue;

        XenIfaceDebugPrint(TRACE, "Evtchn context %p\n", EvtchnContext);
        RemoveEntryList(&EvtchnContext->Entry);
        // EvtchnFree requires PASSIVE_LEVEL and we're inside a lock
        InsertTailList(&ToFree, &EvtchnContext->Entry);
    }
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    Node = ToFree.Flink;
    while (Node->Flink != ToFree.Flink) {
        EvtchnContext = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);
        Node = Node->Flink;

        RemoveEntryList(&EvtchnContext->Entry);
        EvtchnFree(Fdo, EvtchnContext);
    }
}

NTSTATUS
XenIfaceIoctl(
    __in  PXENIFACE_FDO     Fdo,
    __in  PIRP              Irp
    )
{
    NTSTATUS            status;
    PIO_STACK_LOCATION  Stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID               Buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG               InLen = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG               OutLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    status = STATUS_DEVICE_NOT_READY;
    if (Fdo->InterfacesAcquired == FALSE)
        goto done;

    switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
        // store
    case IOCTL_XENIFACE_STORE_READ:
        status = IoctlStoreRead(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_WRITE:
        status = IoctlStoreWrite(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_STORE_DIRECTORY:
        status = IoctlStoreDirectory(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_REMOVE:
        status = IoctlStoreRemove(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_STORE_SET_PERMISSIONS:
        status = IoctlStoreSetPermissions(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_STORE_ADD_WATCH:
        status = IoctlStoreAddWatch(Fdo, (PCHAR)Buffer, InLen, OutLen, Stack->FileObject, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_REMOVE_WATCH:
        status = IoctlStoreRemoveWatch(Fdo, (PCHAR)Buffer, InLen, OutLen, Stack->FileObject);
        break;

        // evtchn
    case IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND:
        status = IoctlEvtchnBindUnbound(Fdo, (PCHAR)Buffer, InLen, OutLen, Stack->FileObject, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN:
        status = IoctlEvtchnBindInterdomain(Fdo, (PCHAR)Buffer, InLen, OutLen, Stack->FileObject, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_EVTCHN_CLOSE:
        status = IoctlEvtchnClose(Fdo, (PCHAR)Buffer, InLen, OutLen, Stack->FileObject);
        break;

    case IOCTL_XENIFACE_EVTCHN_NOTIFY:
        status = IoctlEvtchnNotify(Fdo, (PCHAR)Buffer, InLen, OutLen, Stack->FileObject);
        break;

    case IOCTL_XENIFACE_EVTCHN_UNMASK:
        status = IoctlEvtchnUnmask(Fdo, (PCHAR)Buffer, InLen, OutLen, Stack->FileObject);
        break;

        // gnttab
    case IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS:
        status = IoctlGnttabPermitForeignAccess(Fdo, (PCHAR)Buffer, InLen, OutLen, Irp);
        break;

    case IOCTL_XENIFACE_GNTTAB_GET_GRANT_RESULT:
        status = IoctlGnttabGetGrantResult(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS:
        status = IoctlGnttabRevokeForeignAccess(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES:
        status = IoctlGnttabMapForeignPages(Fdo, (PCHAR)Buffer, InLen, OutLen, Irp);
        break;

    case IOCTL_XENIFACE_GNTTAB_GET_MAP_RESULT:
        status = IoctlGnttabGetMapResult(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES:
        status = IoctlGnttabUnmapForeignPages(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

done:

    Irp->IoStatus.Status = status;

    if (status != STATUS_PENDING)
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
