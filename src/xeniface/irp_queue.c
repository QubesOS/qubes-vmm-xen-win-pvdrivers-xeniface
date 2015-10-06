#include "driver.h"
#include "irp_queue.h"
#include "log.h"
#include "ioctls.h"

// Cancel-safe IRP queue implementation

NTSTATUS
CsqInsertIrpEx(
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp,
    _In_  PVOID   InsertContext // PXENIFACE_CONTEXT_ID
    )
{
    PXENIFACE_FDO Fdo;

    Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);

    // Fail if a request with the same ID already exists.
    if (CsqPeekNextIrp(Csq, NULL, InsertContext) != NULL)
        return STATUS_INVALID_PARAMETER;

    InsertTailList(&Fdo->IrpList, &Irp->Tail.Overlay.ListEntry);
    return STATUS_SUCCESS;
}

VOID
CsqRemoveIrp(
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp
    )
{
    UNREFERENCED_PARAMETER(Csq);

    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

PIRP
CsqPeekNextIrp(
    _In_      PIO_CSQ Csq,
    _In_opt_  PIRP    Irp,
    _In_opt_  PVOID   PeekContext // PXENIFACE_CONTEXT_ID
    )
{
    PXENIFACE_FDO        Fdo;
    PIRP                 NextIrp = NULL;
    PLIST_ENTRY          Head, NextEntry;
    PXENIFACE_CONTEXT_ID Id, TargetId;

    Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);
    TargetId = PeekContext;
    Head = &Fdo->IrpList;

    // If the IRP is NULL, we will start peeking from the list head,
    // else we will start from that IRP onwards. This is done under the
    // assumption that new IRPs are always inserted at the tail.

    if (Irp == NULL) {
        NextEntry = Head->Flink;
    } else {
        NextEntry = Irp->Tail.Overlay.ListEntry.Flink;
    }

    while (NextEntry != Head) {
        NextIrp = CONTAINING_RECORD(NextEntry, IRP, Tail.Overlay.ListEntry);

        if (PeekContext) {
            Id = NextIrp->Tail.Overlay.DriverContext[0];
            if (Id->RequestId == TargetId->RequestId && Id->Process == TargetId->Process)
                break;
        } else {
            break;
        }
        NextIrp = NULL;
        NextEntry = NextEntry->Flink;
    }

    return NextIrp;
}

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Acquires_lock_(CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue)->IrpQueueLock)
VOID
CsqAcquireLock(
    _In_  PIO_CSQ Csq,
    _Out_ PKIRQL  Irql
    )
{
    PXENIFACE_FDO Fdo;

    Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);

    KeAcquireSpinLock(&Fdo->IrpQueueLock, Irql);
}

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue)->IrpQueueLock)
VOID
CsqReleaseLock(
    _In_  PIO_CSQ Csq,
    _In_  KIRQL   Irql
    )
{
    PXENIFACE_FDO Fdo;

    Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);

    KeReleaseSpinLock(&Fdo->IrpQueueLock, Irql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
CsqCompleteCanceledIrp(
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp
    )
{
    PXENIFACE_FDO Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);
    PIO_WORKITEM WorkItem;

    XenIfaceDebugPrint(TRACE, "Irp %p, IRQL %d\n",
                       Irp, KeGetCurrentIrql());

    // This is not guaranteed to run at PASSIVE_LEVEL, so queue a work item
    // to perform actual cleanup/IRP completion.

    WorkItem = IoAllocateWorkItem(Fdo->Dx->DeviceObject);
    Irp->Tail.Overlay.DriverContext[1] = WorkItem; // store so the work item can free it
    IoQueueWorkItem(WorkItem, CompleteGnttabIrp, DelayedWorkQueue, Irp);
}
