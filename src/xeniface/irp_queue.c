#include "driver.h"
#include "log.h"
#include "ioctls.h"

// Cancel-safe IRP queue implementation

VOID
CsqInsertIrp(
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp
    )
{
    PXENIFACE_FDO Fdo;

    Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);
    InsertTailList(&Fdo->IrpList, &Irp->Tail.Overlay.ListEntry);
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
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp,
    _In_  PVOID   PeekContext
    )
{
    PXENIFACE_FDO        Fdo;
    PIRP                 NextIrp = NULL;
    PLIST_ENTRY          Head, NextEntry;
    PXENIFACE_CONTEXT_ID Id, TargetId;

    Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);
    TargetId = PeekContext;
    Head = &Fdo->IrpList;

    //
    // If the IRP is NULL, we will start peeking from the listhead, else
    // we will start from that IRP onwards. This is done under the
    // assumption that new IRPs are always inserted at the tail.
    //

    if (Irp == NULL)
    {
        NextEntry = Head->Flink;
    }
    else
    {
        NextEntry = Irp->Tail.Overlay.ListEntry.Flink;
    }

    while (NextEntry != Head)
    {
        NextIrp = CONTAINING_RECORD(NextEntry, IRP, Tail.Overlay.ListEntry);

        if (PeekContext)
        {
            Id = NextIrp->Tail.Overlay.DriverContext[0];
            if (Id->RequestId == TargetId->RequestId && Id->Process == TargetId->Process)
                break;
        }
        else
        {
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
    _In_                                       PIO_CSQ Csq,
    _Out_ _At_(*Irql, _Post_ _IRQL_saves_)     PKIRQL  Irql
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
    _In_                    PIO_CSQ Csq,
    _In_ _IRQL_restores_    KIRQL   Irql
    )
{
    PXENIFACE_FDO Fdo;

    Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);

    KeReleaseSpinLock(&Fdo->IrpQueueLock, Irql);
}

VOID
CsqCompleteCanceledIrp(
    _In_  PIO_CSQ             Csq,
    _In_  PIRP                Irp
    )
{
    PXENIFACE_FDO Fdo = CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue);
    PXENIFACE_CONTEXT_ID Id = Irp->Tail.Overlay.DriverContext[0];

    XenIfaceDebugPrint(TRACE, "Irp %p, Context %p, Process %p, Id %lu, Type %d, IRQL %d\n",
                       Irp, Id, Id->Process, Id->RequestId, Id->Type, KeGetCurrentIrql());

    switch (Id->Type)
    {
    case XENIFACE_CONTEXT_GRANT:
        GnttabFreeGrant(Fdo, (PXENIFACE_GRANT_CONTEXT)Id);
        break;

    case XENIFACE_CONTEXT_MAP:
        GnttabFreeMap(Fdo, (PXENIFACE_MAP_CONTEXT)Id);
        break;

    default:
        ASSERT(FALSE);

    }

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}
