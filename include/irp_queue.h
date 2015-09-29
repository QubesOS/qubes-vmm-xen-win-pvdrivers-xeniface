#ifndef _IRP_QUEUE_H_
#define _IRP_QUEUE_H_

#include <ntddk.h>

NTSTATUS
CsqInsertIrpEx(
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp,
    _In_  PVOID   InsertContext
    );

VOID CsqRemoveIrp(
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp
    );

PIRP CsqPeekNextIrp(
    _In_      PIO_CSQ Csq,
    _In_opt_  PIRP    Irp,
    _In_opt_  PVOID   PeekContext // PXENIFACE_CONTEXT_ID
    );

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Acquires_lock_(CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue)->IrpQueueLock)
VOID CsqAcquireLock(
    _In_                                       PIO_CSQ Csq,
    _Out_ _At_(*Irql, _Post_ _IRQL_saves_)     PKIRQL  Irql
    );

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue)->IrpQueueLock)
VOID CsqReleaseLock(
    _In_                    PIO_CSQ Csq,
    _In_ _IRQL_restores_    KIRQL   Irql
    );

VOID CsqCompleteCanceledIrp(
    _In_  PIO_CSQ             Csq,
    _In_  PIRP                Irp
    );

#endif
