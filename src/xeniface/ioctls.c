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

#define XENSTORE_ABS_PATH_MAX 3072
#define XENSTORE_REL_PATH_MAX 2048

#if DBG
// debug helper
void DumpLists(PXENIFACE_FDO Fdo, PCHAR caller)
{
    PLIST_ENTRY Node;
    PXENIFACE_GRANT_CONTEXT GrantRecord;
    PXENIFACE_MAP_CONTEXT MapRecord;
    PXENIFACE_EVTCHN_CONTEXT EvtchnRecord;
    PXENIFACE_STORE_CONTEXT StoreRecord;

    XenIfaceDebugPrint(TRACE, "##### %s #####\n", caller);
    XenIfaceDebugPrint(TRACE, "--- GRANT ---\n");
    Node = Fdo->GnttabGrantList.Flink;
    while (Node->Flink != Fdo->GnttabGrantList.Flink) {
        GrantRecord = CONTAINING_RECORD(Node, XENIFACE_GRANT_CONTEXT, Entry);
        Node = Node->Flink;
        XenIfaceDebugPrint(TRACE, "%p: Process %p, %d pages, KVA %p\n", GrantRecord, GrantRecord->Process, GrantRecord->NumberPages, GrantRecord->KernelVa);
    }
    XenIfaceDebugPrint(TRACE, "-------------\n");

    XenIfaceDebugPrint(TRACE, "--- MAP ---\n");
    Node = Fdo->GnttabMapList.Flink;
    while (Node->Flink != Fdo->GnttabMapList.Flink) {
        MapRecord = CONTAINING_RECORD(Node, XENIFACE_MAP_CONTEXT, Entry);
        Node = Node->Flink;
        XenIfaceDebugPrint(TRACE, "%p: Process %p, %d pages, KVA %p\n", MapRecord, MapRecord->Process, MapRecord->NumberPages, MapRecord->KernelVa);
    }
    XenIfaceDebugPrint(TRACE, "-----------\n");

    XenIfaceDebugPrint(TRACE, "--- EVTCHN ---\n");
    Node = Fdo->EvtchnList.Flink;
    while (Node->Flink != Fdo->EvtchnList.Flink) {
        EvtchnRecord = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);
        Node = Node->Flink;
        XenIfaceDebugPrint(TRACE, "%p: Process %p, Port %d\n", EvtchnRecord, EvtchnRecord->Process, EvtchnRecord->LocalPort);
    }
    XenIfaceDebugPrint(TRACE, "--------------\n");

    XenIfaceDebugPrint(TRACE, "--- STORE ---\n");
    Node = Fdo->EvtchnList.Flink;
    while (Node->Flink != Fdo->EvtchnList.Flink) {
        StoreRecord = CONTAINING_RECORD(Node, XENIFACE_STORE_CONTEXT, Entry);
        Node = Node->Flink;
        XenIfaceDebugPrint(TRACE, "%p: Process %p, Watch %p\n", StoreRecord, StoreRecord->Process, StoreRecord->Watch);
    }
    XenIfaceDebugPrint(TRACE, "-------------\n");
}
#endif

static NTSTATUS
CaptureBuffer(
    IN  PVOID Buffer,
    IN  ULONG Length,
    OUT PVOID *CapturedBuffer
    )
{
    NTSTATUS Status;
    PVOID TempBuffer = NULL;

    if (Length == 0) {
        *CapturedBuffer = NULL;
        return STATUS_SUCCESS;
    }

    Status = STATUS_NO_MEMORY;
    TempBuffer = ExAllocatePoolWithTag(NonPagedPool, Length, XENIFACE_POOL_TAG);
    if (TempBuffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = STATUS_SUCCESS;

#pragma prefast(suppress: 6320) // we want to catch all exceptions
    try {
        ProbeForRead(Buffer, Length, 1);
        RtlCopyMemory(TempBuffer, Buffer, Length);
    } except(EXCEPTION_EXECUTE_HANDLER) {
        XenIfaceDebugPrint(ERROR, "Exception while probing/reading buffer at %p, size 0x%lx\n", Buffer, Length);
        ExFreePoolWithTag(TempBuffer, XENIFACE_POOL_TAG);
        TempBuffer = NULL;
        Status = GetExceptionCode();
    }

    *CapturedBuffer = TempBuffer;

    return Status;
 }

static VOID
FreeCapturedBuffer(
    IN  PVOID CapturedBuffer
    )
{
    if (CapturedBuffer != NULL) {
        ExFreePoolWithTag(CapturedBuffer, XENIFACE_POOL_TAG);
    }
}

static FORCEINLINE BOOLEAN
__IsValidStr(
    __in  PCHAR             Str,
    __in  ULONG             Len
    )
{
    for ( ; Len--; ++Str) {
        if (*Str == '\0')
            return TRUE;
        if (!isprint((unsigned char)*Str))
            break;
    }
    return FALSE;
}

static FORCEINLINE ULONG
__MultiSzLen(
    __in  PCHAR             Str,
    __out PULONG            Count
    )
{
    ULONG Length = 0;
    if (Count)  *Count = 0;
    do {
        for ( ; *Str; ++Str, ++Length) ;
        ++Str; ++Length;
        if (*Count) ++(*Count);
    } while (*Str);
    return Length;
}

static FORCEINLINE VOID
__DisplayMultiSz(
    __in PCHAR              Caller,
    __in PCHAR              Str
    )
{
    PCHAR   Ptr;
    ULONG   Idx;
    ULONG   Len;

    for (Ptr = Str, Idx = 0; *Ptr; ++Idx) {
        Len = (ULONG)strlen(Ptr);
        XenIfaceDebugPrint(INFO, "|%s: [%d]=(%d)->\"%s\"\n", Caller, Idx, Len, Ptr);
        Ptr += (Len + 1);
    }
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlStoreRead(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Read, &Fdo->StoreInterface, NULL, NULL, Buffer, &Value);
    if (!NT_SUCCESS(status))
        goto fail3;

    Length = (ULONG)strlen(Value) + 1;

    status = STATUS_BUFFER_OVERFLOW;
    if (OutLen == 0) {
        XenIfaceDebugPrint(INFO, "(\"%s\")=(%d)\n", Buffer, Length);
        goto done;
    }

    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    XenIfaceDebugPrint(INFO, "(\"%s\")=(%d)->\"%s\"\n", Buffer, Length, Value);

    RtlCopyMemory(Buffer, Value, Length);
    Buffer[Length - 1] = 0;
    status = STATUS_SUCCESS;

done:
    *Info = (ULONG_PTR)Length;
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
    return status;

fail4:
    XenIfaceDebugPrint(ERROR, "Fail4 (\"%s\")=(%d < %d)\n", Buffer, OutLen, Length);
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
fail3:
    XenIfaceDebugPrint(ERROR, "Fail3 (\"%s\")\n", Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlStoreWrite(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0 || OutLen != 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    Length = (ULONG)strlen(Buffer) + 1;
    Value = Buffer + Length;

    if (!__IsValidStr(Value, InLen - Length))
        goto fail3;

    status = XENBUS_STORE(Printf, &Fdo->StoreInterface, NULL, NULL, Buffer, Value);
    if (!NT_SUCCESS(status))
        goto fail4;

    XenIfaceDebugPrint(INFO, "(\"%s\"=\"%s\")\n", Buffer, Value);
    return status;

fail4:
    XenIfaceDebugPrint(ERROR, "Fail4 (\"%s\")\n", Value);
fail3:
    XenIfaceDebugPrint(ERROR, "Fail3 (\"%s\")\n", Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlStoreDirectory(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;
    ULONG       Count;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Directory, &Fdo->StoreInterface, NULL, NULL, Buffer, &Value);
    if (!NT_SUCCESS(status))
        goto fail3;

    Length = __MultiSzLen(Value, &Count) + 1;

    status = STATUS_BUFFER_OVERFLOW;
    if (OutLen == 0) {
        XenIfaceDebugPrint(INFO, "(\"%s\")=(%d)(%d)\n", Buffer, Length, Count);
        goto done;
    }

    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    XenIfaceDebugPrint(INFO, "(\"%s\")=(%d)(%d)\n", Buffer, Length, Count);
#if DBG
    __DisplayMultiSz(__FUNCTION__, Value);
#endif

    RtlCopyMemory(Buffer, Value, Length);
    Buffer[Length - 2] = 0;
    Buffer[Length - 1] = 0;
    status = STATUS_SUCCESS;

done:
    *Info = (ULONG_PTR)Length;
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
    return status;

fail4:
    XenIfaceDebugPrint(ERROR, "Fail4 (\"%s\")=(%d < %d)\n", Buffer, OutLen, Length);
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
fail3:
    XenIfaceDebugPrint(ERROR, "Fail3 (\"%s\")\n", Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlStoreRemove(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS    status;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0 || OutLen != 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Remove, &Fdo->StoreInterface, NULL, NULL, Buffer);
    if (!NT_SUCCESS(status))
        goto fail3;

    XenIfaceDebugPrint(INFO, "(\"%s\")\n", Buffer);
    return status;

fail3:
    XenIfaceDebugPrint(ERROR, "Fail3 (\"%s\")\n", Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlStoreSetPermissions(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PSTORE_SET_PERMISSIONS_IN In = (PSTORE_SET_PERMISSIONS_IN)Buffer;
    ULONG Index;
    PCHAR Path;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen < sizeof(STORE_SET_PERMISSIONS_IN) || OutLen != 0)
        goto fail1;

    if (InLen < sizeof(STORE_SET_PERMISSIONS_IN) + In->NumberPermissions * sizeof(XENBUS_STORE_PERMISSION))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (In->PathLength == 0 || In->PathLength > XENSTORE_ABS_PATH_MAX)
        goto fail3;

    status = CaptureBuffer(In->Path, In->PathLength, &Path);
    if (!NT_SUCCESS(status))
        goto fail4;

    Path[In->PathLength - 1] = 0;
    XenIfaceDebugPrint(INFO, "> (Path: '%s', NumberPermissions: %lu)\n", Path, In->NumberPermissions);

    for (Index = 0; Index < In->NumberPermissions; Index++) {
        XenIfaceDebugPrint(INFO, "> (%lu: Domain %d, Mask 0x%x)\n", Index, In->Permissions[Index].Domain, In->Permissions[Index].Mask);
        if ((In->Permissions[Index].Mask & ~XENBUS_STORE_ALLOWED_PERMISSIONS) != 0)
            goto fail5;
    }

    status = XENBUS_STORE(PermissionsSet,
                          &Fdo->StoreInterface,
                          NULL, // transaction
                          NULL, // prefix
                          Path,
                          In->Permissions,
                          In->NumberPermissions);

    if (!NT_SUCCESS(status))
        goto fail6;

    FreeCapturedBuffer(Path);
    return status;

fail6:
    XenIfaceDebugPrint(ERROR, "Fail6\n");
fail5:
    XenIfaceDebugPrint(ERROR, "Fail5\n");
    FreeCapturedBuffer(Path);
fail4:
    XenIfaceDebugPrint(ERROR, "Fail4\n");
fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlStoreAddWatch(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PSTORE_ADD_WATCH_IN In = (PSTORE_ADD_WATCH_IN)Buffer;
    PSTORE_ADD_WATCH_OUT Out = (PSTORE_ADD_WATCH_OUT)Buffer;
    PCHAR Path;
    PXENIFACE_STORE_CONTEXT Context;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(STORE_ADD_WATCH_IN) || OutLen != sizeof(STORE_ADD_WATCH_OUT))
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (In->PathLength == 0 || In->PathLength > XENSTORE_ABS_PATH_MAX)
        goto fail2;

    status = CaptureBuffer(In->Path, In->PathLength, &Path);
    if (!NT_SUCCESS(status))
        goto fail3;

    Path[In->PathLength - 1] = 0;

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_STORE_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail4;

    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));

    Context->Process = PsGetCurrentProcess();

    status = ObReferenceObjectByHandle(In->Event, EVENT_MODIFY_STATE, *ExEventObjectType, UserMode, &Context->Event, NULL);
    if (!NT_SUCCESS(status))
        goto fail5;

    XenIfaceDebugPrint(INFO, "> (Path '%s', Event %p) Process %p\n", Path, In->Event, Context->Process);

    status = XENBUS_STORE(WatchAdd,
                          &Fdo->StoreInterface,
                          NULL, // prefix
                          Path,
                          Context->Event,
                          &Context->Watch);

    if (!NT_SUCCESS(status))
        goto fail6;

    FreeCapturedBuffer(Path);

    KeAcquireSpinLock(&Fdo->StoreWatchLock, &Irql);
    InsertTailList(&Fdo->StoreWatchList, &Context->Entry);
    KeReleaseSpinLock(&Fdo->StoreWatchLock, Irql);

    XenIfaceDebugPrint(INFO, "< Context %p, Watch %p\n", Context, Context->Watch);

    Out->Context = Context;
    *Info = sizeof(STORE_ADD_WATCH_OUT);

    return status;

fail6:
    XenIfaceDebugPrint(ERROR, "Fail6\n");
fail5:
    XenIfaceDebugPrint(ERROR, "Fail5\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
fail4:
    XenIfaceDebugPrint(ERROR, "Fail4\n");
    FreeCapturedBuffer(Path);
fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static
VOID
StoreWatchFree(
    __in PXENIFACE_FDO Fdo,
    __in PXENIFACE_STORE_CONTEXT Context
    )
{
    NTSTATUS status;

    XenIfaceDebugPrint(TRACE, "Record %p, Watch %p, Process %p\n", Context, Context->Watch, Context->Process);
    status = XENBUS_STORE(WatchRemove,
                          &Fdo->StoreInterface,
                          Context->Watch);

    ASSERT(NT_SUCCESS(status)); // this is fatal since we'd leave an active watch without cleaning it up

    ObDereferenceObject(Context->Event);
    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlStoreRemoveWatch(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PSTORE_REMOVE_WATCH_IN In = (PSTORE_REMOVE_WATCH_IN)Buffer;
    PXENIFACE_STORE_CONTEXT Context = NULL;
    KIRQL Irql;
    PLIST_ENTRY Node;
    PEPROCESS CurrentProcess;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(STORE_REMOVE_WATCH_IN) || OutLen != 0)
        goto fail1;

    CurrentProcess = PsGetCurrentProcess();
    XenIfaceDebugPrint(INFO, "> (Context %p) Process %p\n", In->Context, CurrentProcess);

    KeAcquireSpinLock(&Fdo->StoreWatchLock, &Irql);
    Node = Fdo->StoreWatchList.Flink;
    while (Node->Flink != Fdo->StoreWatchList.Flink) {
        Context = CONTAINING_RECORD(Node, XENIFACE_STORE_CONTEXT, Entry);

        Node = Node->Flink;
        if (Context != In->Context || Context->Process != CurrentProcess)
            continue;

        RemoveEntryList(&Context->Entry);
        break;
    }
    KeReleaseSpinLock(&Fdo->StoreWatchLock, Irql);

    status = STATUS_NOT_FOUND;
    if (Context == NULL || Context != In->Context)
        goto fail2;

    StoreWatchFree(Fdo, Context);

    return STATUS_SUCCESS;

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
EvtchnDpc(
    __in     PKDPC Dpc,
    __in_opt PVOID Context,
    __in_opt PVOID Argument1,
    __in_opt PVOID Argument2
    )
{
    PXENIFACE_EVTCHN_CONTEXT Ctx = (PXENIFACE_EVTCHN_CONTEXT)Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);
    ASSERT(Context != NULL);

    XenIfaceDebugPrint(TRACE, "Signaled Channel %p, LocalPort %d, IRQL %d\n", Ctx->Channel, Ctx->LocalPort, KeGetCurrentIrql());
    KeSetEvent(Ctx->Event, 0, FALSE);
}

_Function_class_(KSERVICE_ROUTINE)
_IRQL_requires_(HIGH_LEVEL)
_IRQL_requires_same_
static DECLSPEC_NOINLINE
BOOLEAN
EvtchnCallback(
    __in     PKINTERRUPT Interrupt,
    __in_opt PVOID Argument
    )
{
    PXENIFACE_EVTCHN_CONTEXT Context = (PXENIFACE_EVTCHN_CONTEXT)Argument;

    UNREFERENCED_PARAMETER(Interrupt);
    ASSERT(Context != NULL);

    // we're running at high irql, queue a dpc to signal the event
    KeInsertQueueDpc(&Context->Dpc, NULL, NULL);

    return TRUE;
}

static
VOID
EvtchnFree(
    __in PXENIFACE_FDO Fdo,
    __in PXENIFACE_EVTCHN_CONTEXT Context
    )
{
    XenIfaceDebugPrint(TRACE, "Record %p, LocalPort %d, Process %p\n", Context, Context->LocalPort, Context->Process);
    XENBUS_EVTCHN(Close, &Fdo->EvtchnInterface, Context->Channel);
    ObDereferenceObject(Context->Event);
    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

// EvtchnLock must be held
static
PXENIFACE_EVTCHN_CONTEXT
EvtchnFindChannel(
    __in PXENIFACE_FDO Fdo,
    __in ULONG LocalPort
)
{
    PXENIFACE_EVTCHN_CONTEXT Record, Found = NULL;
    PLIST_ENTRY Node;

    Node = Fdo->EvtchnList.Flink;
    while (Node->Flink != Fdo->EvtchnList.Flink) {
        Record = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);

        Node = Node->Flink;
        if (Record->LocalPort != LocalPort)
            continue;

        Found = Record;
        break;
    }

    return Found;
}

// Process creation/destruction notify routine.
// Used for cleaning up of allocated event channels and grants/maps/store watches.
// Runs at PASSIVE_LEVEL and if Create==FALSE, in the context of the process being destroyed.
VOID
XenifaceProcessNotify(
    __in HANDLE ParentId,
    __in HANDLE ProcessId,
    __in BOOLEAN Create
    )
{
    PEPROCESS CurrentProcess;
    PLIST_ENTRY Node;
    PXENIFACE_EVTCHN_CONTEXT EvtchnRecord;
    PXENIFACE_GRANT_CONTEXT GnttabRecord;
    PXENIFACE_MAP_CONTEXT MapRecord;
    PXENIFACE_STORE_CONTEXT StoreRecord;
    KIRQL Irql;
    LIST_ENTRY ToFree;

    UNREFERENCED_PARAMETER(ParentId);
    UNREFERENCED_PARAMETER(ProcessId);

    // we're only interested in process destruction for cleanup purposes
    if (Create)
        return;

    CurrentProcess = PsGetCurrentProcess();
    XenIfaceDebugPrint(TRACE, "Process %p\n", CurrentProcess);

    // store watches
    KeAcquireSpinLock(&FdoGlobal->StoreWatchLock, &Irql);
    Node = FdoGlobal->StoreWatchList.Flink;
    while (Node->Flink != FdoGlobal->StoreWatchList.Flink) {
        StoreRecord = CONTAINING_RECORD(Node, XENIFACE_STORE_CONTEXT, Entry);

        Node = Node->Flink;
        if (StoreRecord->Process != CurrentProcess)
            continue;

        XenIfaceDebugPrint(TRACE, "Process %p, StoreRecord %p\n", CurrentProcess, StoreRecord);
        RemoveEntryList(&StoreRecord->Entry);
        StoreWatchFree(FdoGlobal, StoreRecord);
    }
    KeReleaseSpinLock(&FdoGlobal->StoreWatchLock, Irql);

    // grants
    InitializeListHead(&ToFree);
    KeAcquireSpinLock(&FdoGlobal->GnttabGrantLock, &Irql);
    Node = FdoGlobal->GnttabGrantList.Flink;
    while (Node->Flink != FdoGlobal->GnttabGrantList.Flink) {
        GnttabRecord = CONTAINING_RECORD(Node, XENIFACE_GRANT_CONTEXT, Entry);

        Node = Node->Flink;
        if (GnttabRecord->Process != CurrentProcess)
            continue;

        XenIfaceDebugPrint(TRACE, "Process %p, GnttabRecord %p\n", CurrentProcess, GnttabRecord);
        // can't free/unmap user memory here since locks raise IRQL to DPC_LEVEL
        RemoveEntryList(&GnttabRecord->Entry);
        InsertTailList(&ToFree, &GnttabRecord->Entry);
    }
    KeReleaseSpinLock(&FdoGlobal->GnttabGrantLock, Irql);

    Node = ToFree.Flink;
    while (Node->Flink != ToFree.Flink) {
        GnttabRecord = CONTAINING_RECORD(Node, XENIFACE_GRANT_CONTEXT, Entry);
        Node = Node->Flink;

        RemoveEntryList(&GnttabRecord->Entry);
        GnttabFreeGrant(FdoGlobal, GnttabRecord);
    }

    // maps
    InitializeListHead(&ToFree);
    KeAcquireSpinLock(&FdoGlobal->GnttabMapLock, &Irql);
    Node = FdoGlobal->GnttabMapList.Flink;
    while (Node->Flink != FdoGlobal->GnttabMapList.Flink) {
        MapRecord = CONTAINING_RECORD(Node, XENIFACE_MAP_CONTEXT, Entry);

        Node = Node->Flink;
        if (MapRecord->Process != CurrentProcess)
            continue;

        XenIfaceDebugPrint(TRACE, "Process %p, MapRecord %p\n", CurrentProcess, MapRecord);
        // can't free/unmap user memory here since locks raise IRQL to DPC_LEVEL
        RemoveEntryList(&MapRecord->Entry);
        InsertTailList(&ToFree, &MapRecord->Entry);
    }
    KeReleaseSpinLock(&FdoGlobal->GnttabMapLock, Irql);

    Node = ToFree.Flink;
    while (Node->Flink != ToFree.Flink) {
        MapRecord = CONTAINING_RECORD(Node, XENIFACE_MAP_CONTEXT, Entry);
        Node = Node->Flink;

        RemoveEntryList(&MapRecord->Entry);
        GnttabFreeMap(FdoGlobal, MapRecord);
    }

    // event channels, last because grants/maps can use them for unmap notifications
    KeAcquireSpinLock(&FdoGlobal->EvtchnLock, &Irql);
    Node = FdoGlobal->EvtchnList.Flink;
    while (Node->Flink != FdoGlobal->EvtchnList.Flink) {
        EvtchnRecord = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);

        Node = Node->Flink;
        if (EvtchnRecord->Process != CurrentProcess)
            continue;

        XenIfaceDebugPrint(TRACE, "Process %p, EvtchnRecord %p\n", CurrentProcess, EvtchnRecord);
        RemoveEntryList(&EvtchnRecord->Entry);
        EvtchnFree(FdoGlobal, EvtchnRecord);
    }
    KeReleaseSpinLock(&FdoGlobal->EvtchnLock, Irql);
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnBindUnboundPort(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PEVTCHN_BIND_UNBOUND_PORT_IN In = (PEVTCHN_BIND_UNBOUND_PORT_IN)Buffer;
    PEVTCHN_BIND_UNBOUND_PORT_OUT Out = (PEVTCHN_BIND_UNBOUND_PORT_OUT)Buffer;
    PXENIFACE_EVTCHN_CONTEXT Context;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(EVTCHN_BIND_UNBOUND_PORT_IN) || OutLen != sizeof(EVTCHN_BIND_UNBOUND_PORT_OUT))
        goto fail1;

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_EVTCHN_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail2;

    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    Context->Process = PsGetCurrentProcess();

    XenIfaceDebugPrint(INFO, "> (RemoteDomain %d, Mask %d) Process %p\n",
                       In->RemoteDomain, In->Mask, Context->Process);

    status = ObReferenceObjectByHandle(In->Event, EVENT_MODIFY_STATE, *ExEventObjectType, UserMode, &Context->Event, NULL);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_UNSUCCESSFUL;
    Context->Channel = XENBUS_EVTCHN(Open,
                                     &Fdo->EvtchnInterface,
                                     XENBUS_EVTCHN_TYPE_UNBOUND,
                                     EvtchnCallback,
                                     Context,
                                     In->RemoteDomain,
                                     FALSE);
    if (Context->Channel == NULL)
        goto fail4;

    Context->LocalPort = XENBUS_EVTCHN(GetPort,
                                       &Fdo->EvtchnInterface,
                                       Context->Channel);

    KeInitializeDpc(&Context->Dpc, EvtchnDpc, Context);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    InsertTailList(&Fdo->EvtchnList, &Context->Entry);
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    Out->LocalPort = Context->LocalPort;
    *Info = sizeof(EVTCHN_BIND_UNBOUND_PORT_OUT);

    if (!In->Mask) {
        XENBUS_EVTCHN(Unmask,
                      &Fdo->EvtchnInterface,
                      Context->Channel,
                      FALSE);
    }

    XenIfaceDebugPrint(INFO, "< LocalPort %d, Context %p\n", Context->LocalPort, Context);
    return STATUS_SUCCESS;

fail4:
    XenIfaceDebugPrint(ERROR, "Fail4\n");
    ObDereferenceObject(Context->Event);
fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnBindInterdomain(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PEVTCHN_BIND_INTERDOMAIN_IN In = (PEVTCHN_BIND_INTERDOMAIN_IN)Buffer;
    PEVTCHN_BIND_INTERDOMAIN_OUT Out = (PEVTCHN_BIND_INTERDOMAIN_OUT)Buffer;
    PXENIFACE_EVTCHN_CONTEXT Context;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(EVTCHN_BIND_INTERDOMAIN_IN) || OutLen != sizeof(EVTCHN_BIND_INTERDOMAIN_OUT))
        goto fail1;

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_EVTCHN_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail2;

    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    Context->Process = PsGetCurrentProcess();

    XenIfaceDebugPrint(INFO, "> (RemoteDomain %d, RemotePort %d, Mask %d) Process %p\n",
                       In->RemoteDomain, In->RemotePort, In->Mask, Context->Process);

    status = ObReferenceObjectByHandle(In->Event, EVENT_MODIFY_STATE, *ExEventObjectType, UserMode, &Context->Event, NULL);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_UNSUCCESSFUL;
    Context->Channel = XENBUS_EVTCHN(Open,
                                     &Fdo->EvtchnInterface,
                                     XENBUS_EVTCHN_TYPE_INTER_DOMAIN,
                                     EvtchnCallback,
                                     Context,
                                     In->RemoteDomain,
                                     In->RemotePort,
                                     FALSE);
    if (Context->Channel == NULL)
        goto fail4;

    Context->LocalPort = XENBUS_EVTCHN(GetPort,
                                       &Fdo->EvtchnInterface,
                                       Context->Channel);

    KeInitializeDpc(&Context->Dpc, EvtchnDpc, Context);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    InsertTailList(&Fdo->EvtchnList, &Context->Entry);
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    Out->LocalPort = Context->LocalPort;

    *Info = sizeof(EVTCHN_BIND_INTERDOMAIN_OUT);

    if (!In->Mask) {
        XENBUS_EVTCHN(Unmask,
                      &Fdo->EvtchnInterface,
                      Context->Channel,
                      FALSE);
    }

    XenIfaceDebugPrint(INFO, "< LocalPort %d, Context %p\n", Context->LocalPort, Context);

    return STATUS_SUCCESS;

fail4:
    XenIfaceDebugPrint(ERROR, "Fail4\n");
    ObDereferenceObject(Context->Event);
fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnClose(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PEVTCHN_CLOSE_IN In = (PEVTCHN_CLOSE_IN)Buffer;
    PXENIFACE_EVTCHN_CONTEXT Record = NULL;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(EVTCHN_CLOSE_IN) || OutLen != 0)
        goto fail1;

    XenIfaceDebugPrint(INFO, "> (LocalPort %d)\n", In->LocalPort);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    Record = EvtchnFindChannel(Fdo, In->LocalPort);
    if (Record != NULL) {
        RemoveEntryList(&Record->Entry);
        EvtchnFree(Fdo, Record);
    }
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    status = STATUS_INVALID_PARAMETER;
    if (Record == NULL)
        goto fail2;

    XenIfaceDebugPrint(TRACE, "Context %p\n", Record);

    return STATUS_SUCCESS;

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
EvtchnNotify(
    __in  PXENIFACE_FDO     Fdo,
    __in  PEPROCESS         Process,
    __in  ULONG             LocalPort
    )
{
    NTSTATUS status;
    PXENIFACE_EVTCHN_CONTEXT Record = NULL;
    KIRQL Irql;

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);

    Record = EvtchnFindChannel(Fdo, LocalPort);

    status = STATUS_NOT_FOUND;
    if (Record == NULL)
        goto fail1;

    status = STATUS_ACCESS_DENIED;
    if (Record->Process != Process)
        goto fail2;

    XENBUS_EVTCHN(Send, &Fdo->EvtchnInterface, Record->Channel);

    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    return STATUS_SUCCESS;

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnNotify(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PEVTCHN_NOTIFY_IN In = (PEVTCHN_NOTIFY_IN)Buffer;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(EVTCHN_NOTIFY_IN) || OutLen != 0)
        goto fail1;
#if DBG
    XenIfaceDebugPrint(INFO, "> (LocalPort %d)\n", In->LocalPort);
#endif

    return EvtchnNotify(Fdo, PsGetCurrentProcess(), In->LocalPort);

fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnUnmask(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PEVTCHN_UNMASK_IN In = (PEVTCHN_UNMASK_IN)Buffer;
    PXENIFACE_EVTCHN_CONTEXT Record = NULL;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(EVTCHN_UNMASK_IN) || OutLen != 0)
        goto fail1;

    XenIfaceDebugPrint(INFO, "> (LocalPort %d)\n", In->LocalPort);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);

    Record = EvtchnFindChannel(Fdo, In->LocalPort);

    status = STATUS_INVALID_PARAMETER;
    if (Record == NULL)
        goto fail2;

    XENBUS_EVTCHN(Unmask,
                  &Fdo->EvtchnInterface,
                  Record->Channel,
                  FALSE);

    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    return STATUS_SUCCESS;

fail2:
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);
    XenIfaceDebugPrint(ERROR, "Fail2\n");

fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnStatus(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PEVTCHN_STATUS_IN In = (PEVTCHN_STATUS_IN)Buffer;
    PEVTCHN_STATUS_OUT Out = (PEVTCHN_STATUS_OUT)Buffer;
    PXENIFACE_EVTCHN_CONTEXT Record = NULL;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(EVTCHN_STATUS_IN) || OutLen != sizeof(EVTCHN_STATUS_OUT))
        goto fail1;

    XenIfaceDebugPrint(INFO, "> (LocalPort %d)\n", In->LocalPort);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);

    Record = EvtchnFindChannel(Fdo, In->LocalPort);

    status = STATUS_INVALID_PARAMETER;
    if (Record == NULL)
        goto fail2;

    status = XENBUS_EVTCHN(Status,
                           &Fdo->EvtchnInterface,
                           Record->Channel,
                           &Out->Status);

    if (!NT_SUCCESS(status))
        goto fail3;

    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);
    *Info = sizeof(EVTCHN_STATUS_OUT);

    return status;

fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");

fail2:
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);
    XenIfaceDebugPrint(ERROR, "Fail2\n");

fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
GnttabAcquireLock(
    __in PVOID Argument
    )
{
    PXENIFACE_FDO Fdo = Argument;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Fdo->GnttabGrantLock);
}

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
GnttabReleaseLock(
    __in PVOID Argument
    )
{
    PXENIFACE_FDO Fdo = Argument;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

#pragma prefast(suppress:26110)
    KeReleaseSpinLockFromDpcLevel(&Fdo->GnttabGrantLock);
}

DECLSPEC_NOINLINE
NTSTATUS
GnttabFreeGrant(
    __in PXENIFACE_FDO Fdo,
    __in PXENIFACE_GRANT_CONTEXT Context
    )
{
    NTSTATUS status;
    ULONG Page;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    XenIfaceDebugPrint(INFO, "Record %p\n", Context);

    if (Context->Flags & GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET) {
        ((PCHAR)Context->KernelVa)[Context->NotifyOffset] = 0;
    }

    if (Context->Flags & GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT) {
        status = EvtchnNotify(Fdo, PsGetCurrentProcess(), Context->NotifyPort);

        if (!NT_SUCCESS(status)) // non-fatal, we must free memory
            XenIfaceDebugPrint(ERROR, "failed to notify port %lu: 0x%x\n", Context->NotifyPort, status);
    }

    // unmap from user address space
    MmUnmapLockedPages(Context->UserVa, Context->Mdl);

    // stop sharing
    for (Page = 0; Page < Context->NumberPages; Page++) {
        status = XENBUS_GNTTAB(RevokeForeignAccess,
                               &Fdo->GnttabInterface,
                               Fdo->GnttabCache,
                               FALSE,
                               Context->Grants[Page]);

        if (!NT_SUCCESS(status))
            goto fail1;
    }

    IoFreeMdl(Context->Mdl);

    RtlZeroMemory(Context->KernelVa, Context->NumberPages * PAGE_SIZE);
    ExFreePoolWithTag(Context->KernelVa, XENIFACE_POOL_TAG);

    RtlZeroMemory(Context->Grants, Context->NumberPages * sizeof(PXENBUS_GNTTAB_ENTRY));
    ExFreePoolWithTag(Context->Grants, XENIFACE_POOL_TAG);

    RtlZeroMemory(Context, sizeof(XENIFACE_GRANT_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);

    return STATUS_SUCCESS;

fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x), leaking memory: buffer %p size 0x%x\n",
                       status, Context->KernelVa, Context->NumberPages * PAGE_SIZE);
    // we can't free the memory since the foreign domain still can access it

    IoFreeMdl(Context->Mdl);
    RtlZeroMemory(Context->Grants, Context->NumberPages * sizeof(PXENBUS_GNTTAB_ENTRY));
    ExFreePoolWithTag(Context->Grants, XENIFACE_POOL_TAG);
    RtlZeroMemory(Context, sizeof(XENIFACE_GRANT_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabGrantPages(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PGNTTAB_GRANT_PAGES_IN In = (PGNTTAB_GRANT_PAGES_IN)Buffer;
    PGNTTAB_GRANT_PAGES_OUT Out = (PGNTTAB_GRANT_PAGES_OUT)Buffer;
    PXENIFACE_GRANT_CONTEXT Context;
    KIRQL Irql;
    ULONG Page;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(GNTTAB_GRANT_PAGES_IN))
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if ((In->NumberPages == 0) || (In->NumberPages > 1024 * 1024) ||
        ((In->Flags & GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET) && (In->NotifyOffset >= In->NumberPages * PAGE_SIZE))
        )
        goto fail2;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (OutLen != (sizeof(GNTTAB_GRANT_PAGES_OUT) + sizeof(ULONG) * In->NumberPages))
        goto fail3;

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_GRANT_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail4;

    RtlZeroMemory(Context, sizeof(XENIFACE_GRANT_CONTEXT));
    Context->Process = PsGetCurrentProcess();
    Context->RemoteDomain = In->RemoteDomain;
    Context->NumberPages = In->NumberPages;
    Context->Flags = In->Flags;
    Context->NotifyOffset = In->NotifyOffset;
    Context->NotifyPort = In->NotifyPort;

    XenIfaceDebugPrint(INFO, "> (RemoteDomain %d, NumberPages %lu, Flags 0x%x, Offset 0x%x, Port %d) Process %p\n",
                       Context->RemoteDomain, Context->NumberPages, Context->Flags, Context->NotifyOffset, Context->NotifyPort, Context->Process);

    status = STATUS_NO_MEMORY;
    Context->Grants = ExAllocatePoolWithTag(NonPagedPool, Context->NumberPages * sizeof(PXENBUS_GNTTAB_ENTRY), XENIFACE_POOL_TAG);
    if (Context->Grants == NULL)
        goto fail5;

    RtlZeroMemory(Context->Grants, Context->NumberPages * sizeof(PXENBUS_GNTTAB_ENTRY));

    // allocate memory to share
    status = STATUS_NO_MEMORY;
    Context->KernelVa = ExAllocatePoolWithTag(NonPagedPool, Context->NumberPages * PAGE_SIZE, XENIFACE_POOL_TAG);
    if (Context->KernelVa == NULL)
        goto fail6;

    RtlZeroMemory(Context->KernelVa, Context->NumberPages * PAGE_SIZE);
    Context->Mdl = IoAllocateMdl(Context->KernelVa, Context->NumberPages * PAGE_SIZE, FALSE, FALSE, NULL);
    if (Context->Mdl == NULL)
        goto fail7;

    MmBuildMdlForNonPagedPool(Context->Mdl);
    ASSERT(MmGetMdlByteCount(Context->Mdl) == Context->NumberPages * PAGE_SIZE);

    // perform sharing
    for (Page = 0; Page < Context->NumberPages; Page++) {
        status = XENBUS_GNTTAB(PermitForeignAccess,
                               &Fdo->GnttabInterface,
                               Fdo->GnttabCache,
                               FALSE,
                               Context->RemoteDomain,
                               MmGetMdlPfnArray(Context->Mdl)[Page],
                               (Context->Flags & GNTTAB_GRANT_PAGES_READONLY) != 0,
                               &(Context->Grants[Page]));

// prefast somehow thinks that this call can modify Page...
#pragma prefast(suppress:6385)
        XenIfaceDebugPrint(TRACE, "Grants[%lu] = %p\n", Page, Context->Grants[Page]);
        if (!NT_SUCCESS(status))
            goto fail8;
    }

    // map into user mode
#pragma prefast(suppress: 6320) // we want to catch all exceptions
    __try {
        Context->UserVa = MmMapLockedPagesSpecifyCache(Context->Mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto fail8;
    }

    XenIfaceDebugPrint(INFO, "Record %p, KernelVa %p, UserVa %p\n", Context, Context->KernelVa, Context->UserVa);

    // set output values
    Out->Context = Context;
    Out->Address = Context->UserVa;
    for (Page = 0; Page < Context->NumberPages; Page++) {
        Out->References[Page] = XENBUS_GNTTAB(GetReference,
                                              &Fdo->GnttabInterface,
                                              Context->Grants[Page]);
        XenIfaceDebugPrint(TRACE, "Ref[%lu] = %lu\n", Page, Out->References[Page]);
    }

    KeAcquireSpinLock(&Fdo->GnttabGrantLock, &Irql);
    InsertTailList(&Fdo->GnttabGrantList, &Context->Entry);
    KeReleaseSpinLock(&Fdo->GnttabGrantLock, Irql);

    *Info = sizeof(GNTTAB_GRANT_PAGES_OUT) + sizeof(ULONG) * Context->NumberPages;

    return STATUS_SUCCESS;

fail8:
    XenIfaceDebugPrint(ERROR, "Fail8: Page = %lu\n", Page);

    while (Page > 0) {
        ASSERT(NT_SUCCESS(XENBUS_GNTTAB(RevokeForeignAccess,
                                        &Fdo->GnttabInterface,
                                        Fdo->GnttabCache,
                                        FALSE,
                                        Context->Grants[Page - 1])));

        --Page;
    }
    IoFreeMdl(Context->Mdl);

fail7:
    XenIfaceDebugPrint(ERROR, "Fail7\n");
    ExFreePoolWithTag(Context->KernelVa, XENIFACE_POOL_TAG);

fail6:
    XenIfaceDebugPrint(ERROR, "Fail6\n");
    ExFreePoolWithTag(Context->Grants, XENIFACE_POOL_TAG);

fail5:
    XenIfaceDebugPrint(ERROR, "Fail5\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_GRANT_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);

fail4:
    XenIfaceDebugPrint(ERROR, "Fail4\n");

fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");

fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabUngrantPages(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PGNTTAB_UNGRANT_PAGES_IN In = (PGNTTAB_UNGRANT_PAGES_IN)Buffer;
    PXENIFACE_GRANT_CONTEXT Context = NULL;
    KIRQL Irql;
    PLIST_ENTRY Node;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(GNTTAB_UNGRANT_PAGES_IN))
        goto fail1;

    XenIfaceDebugPrint(INFO, "> Context %p\n", In->Context);
    KeAcquireSpinLock(&Fdo->GnttabGrantLock, &Irql);
    Node = Fdo->GnttabGrantList.Flink;
    while (Node->Flink != Fdo->GnttabGrantList.Flink) {
        Context = CONTAINING_RECORD(Node, XENIFACE_GRANT_CONTEXT, Entry);

        Node = Node->Flink;
        if (Context != In->Context)
            continue;

        RemoveEntryList(&Context->Entry);
        break;
    }
    KeReleaseSpinLock(&Fdo->GnttabGrantLock, Irql);

    status = STATUS_NOT_FOUND;
    if (Context == NULL || Context != In->Context)
        goto fail2;

    return GnttabFreeGrant(Fdo, Context);

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabMapForeignPages(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PGNTTAB_MAP_FOREIGN_PAGES_IN In = (PGNTTAB_MAP_FOREIGN_PAGES_IN)Buffer;
    PGNTTAB_MAP_FOREIGN_PAGES_OUT Out = (PGNTTAB_MAP_FOREIGN_PAGES_OUT)Buffer;
    PXENIFACE_MAP_CONTEXT Context;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen < sizeof(GNTTAB_MAP_FOREIGN_PAGES_IN) || OutLen != sizeof(GNTTAB_MAP_FOREIGN_PAGES_OUT))
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if ((In->NumberPages == 0) || (In->NumberPages > 1024 * 1024) ||
        ((In->Flags & GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET) && (In->NotifyOffset >= In->NumberPages * PAGE_SIZE))
        )
        goto fail2;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(GNTTAB_MAP_FOREIGN_PAGES_IN) + sizeof(ULONG) * In->NumberPages)
        goto fail3;

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_MAP_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail4;

    RtlZeroMemory(Context, sizeof(XENIFACE_MAP_CONTEXT));
    Context->Process = PsGetCurrentProcess();
    Context->RemoteDomain = In->RemoteDomain;
    Context->NumberPages = In->NumberPages;
    Context->Flags = In->Flags;
    Context->NotifyOffset = In->NotifyOffset;
    Context->NotifyPort = In->NotifyPort;

    XenIfaceDebugPrint(INFO, "> (RemoteDomain %d, NumberPages %lu, Flags 0x%x, Offset 0x%x, Port %d) Process %p\n",
                       Context->RemoteDomain, Context->NumberPages, Context->Flags, Context->NotifyOffset, Context->NotifyPort, Context->Process);

    for (ULONG i = 0; i < In->NumberPages; i++)
        XenIfaceDebugPrint(INFO, "> Ref %d\n", In->References[i]);

    status = STATUS_NO_MEMORY;
    Context->Handles = ExAllocatePoolWithTag(NonPagedPool, Context->NumberPages * sizeof(ULONG), XENIFACE_POOL_TAG);
    if (Context->Handles == NULL)
        goto fail5;

    RtlZeroMemory(Context->Handles, Context->NumberPages * sizeof(ULONG));

    status = XENBUS_GNTTAB(MapForeignPages,
                           &Fdo->GnttabInterface,
                           Context->RemoteDomain,
                           Context->NumberPages,
                           In->References,
                           Context->Flags & GNTTAB_GRANT_PAGES_READONLY,
                           &Context->Address,
                           Context->Handles);

    if (!NT_SUCCESS(status))
        goto fail6;

    status = STATUS_NO_MEMORY;
    Context->KernelVa = MmMapIoSpace(Context->Address, Context->NumberPages * PAGE_SIZE, MmCached);
    if (Context->KernelVa == NULL)
        goto fail7;

    status = STATUS_NO_MEMORY;
    Context->Mdl = IoAllocateMdl(Context->KernelVa, Context->NumberPages * PAGE_SIZE, FALSE, FALSE, NULL);
    if (Context->Mdl == NULL)
        goto fail8;

    MmBuildMdlForNonPagedPool(Context->Mdl);

    // map into user mode
#pragma prefast(suppress: 6320) // we want to catch all exceptions
    __try {
        Context->UserVa = MmMapLockedPagesSpecifyCache(Context->Mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto fail9;
    }

    XenIfaceDebugPrint(INFO, "Record %p, Address %p, KernelVa %p, UserVa %p\n", Context, Context->Address, Context->KernelVa, Context->UserVa);

    // set output values
    Out->Context = Context;
    Out->Address = Context->UserVa;

    KeAcquireSpinLock(&Fdo->GnttabMapLock, &Irql);
    InsertTailList(&Fdo->GnttabMapList, &Context->Entry);
    KeReleaseSpinLock(&Fdo->GnttabMapLock, Irql);

    *Info = sizeof(GNTTAB_MAP_FOREIGN_PAGES_OUT);

    return STATUS_SUCCESS;

fail9:
    XenIfaceDebugPrint(ERROR, "Fail9\n");
    IoFreeMdl(Context->Mdl);

fail8:
    XenIfaceDebugPrint(ERROR, "Fail8\n");
    MmUnmapIoSpace(Context->KernelVa, Context->NumberPages * PAGE_SIZE);

fail7:
    XenIfaceDebugPrint(ERROR, "Fail7\n");
    ASSERT(NT_SUCCESS(XENBUS_GNTTAB(UnmapForeignPages,
                                    &Fdo->GnttabInterface,
                                    Context->NumberPages,
                                    Context->Address,
                                    Context->Handles
                                    )));

fail6:
    XenIfaceDebugPrint(ERROR, "Fail6\n");
    ExFreePoolWithTag(Context->Handles, XENIFACE_POOL_TAG);

fail5:
    XenIfaceDebugPrint(ERROR, "Fail5\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_MAP_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);

fail4:
    XenIfaceDebugPrint(ERROR, "Fail4\n");

fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");

fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
GnttabFreeMap(
    __in PXENIFACE_FDO Fdo,
    __in PXENIFACE_MAP_CONTEXT Context
    )
{
    NTSTATUS status;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    XenIfaceDebugPrint(INFO, "Record %p\n", Context);

    if (Context->Flags & GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET) {
        ((PCHAR)Context->KernelVa)[Context->NotifyOffset] = 0;
    }

    if (Context->Flags & GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT) {
        status = EvtchnNotify(Fdo, PsGetCurrentProcess(), Context->NotifyPort);

        if (!NT_SUCCESS(status)) // non-fatal, we must free memory
            XenIfaceDebugPrint(ERROR, "failed to notify port %lu: 0x%x\n", Context->NotifyPort, status);
    }

    // unmap from user address space
    MmUnmapLockedPages(Context->UserVa, Context->Mdl);

    IoFreeMdl(Context->Mdl);

    // unmap from system space
    MmUnmapIoSpace(Context->KernelVa, Context->NumberPages * PAGE_SIZE);

    // undo mapping
    status = XENBUS_GNTTAB(UnmapForeignPages,
                           &Fdo->GnttabInterface,
                           Context->NumberPages,
                           Context->Address,
                           Context->Handles
                           );

    if (!NT_SUCCESS(status))
        goto fail1;

    RtlZeroMemory(Context->Handles, Context->NumberPages * sizeof(ULONG));
    ExFreePoolWithTag(Context->Handles, XENIFACE_POOL_TAG);

    RtlZeroMemory(Context, sizeof(XENIFACE_MAP_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);

    return STATUS_SUCCESS;

fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x), leaking io memory: physical address %p size 0x%x\n",
                       status, Context->Address, Context->NumberPages * PAGE_SIZE);
    // we can't free the memory since it's still mapped
    RtlZeroMemory(Context->Handles, Context->NumberPages * sizeof(ULONG));
    ExFreePoolWithTag(Context->Handles, XENIFACE_POOL_TAG);
    RtlZeroMemory(Context, sizeof(XENIFACE_MAP_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
    return status;
}

static DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabUnmapForeignPages(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PGNTTAB_UNMAP_FOREIGN_PAGES_IN In = (PGNTTAB_UNMAP_FOREIGN_PAGES_IN)Buffer;
    PXENIFACE_MAP_CONTEXT Context = NULL;
    KIRQL Irql;
    PLIST_ENTRY Node;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(GNTTAB_UNMAP_FOREIGN_PAGES_IN) && OutLen != 0)
        goto fail1;

    KeAcquireSpinLock(&Fdo->GnttabMapLock, &Irql);
    Node = Fdo->GnttabMapList.Flink;
    while (Node->Flink != Fdo->GnttabMapList.Flink) {
        Context = CONTAINING_RECORD(Node, XENIFACE_MAP_CONTEXT, Entry);

        Node = Node->Flink;
        if (Context != In->Context)
            continue;

        RemoveEntryList(&Context->Entry);
        break;
    }
    KeReleaseSpinLock(&Fdo->GnttabMapLock, Irql);

    status = STATUS_NOT_FOUND;
    if (Context == NULL || Context != In->Context)
        goto fail2;

    return GnttabFreeMap(Fdo, Context);

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

NTSTATUS
XenIFaceIoctl(
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
        status = IoctlStoreAddWatch(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_REMOVE_WATCH:
        status = IoctlStoreRemoveWatch(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

        // evtchn
    case IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND_PORT:
        status = IoctlEvtchnBindUnboundPort(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN:
        status = IoctlEvtchnBindInterdomain(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_EVTCHN_CLOSE:
        status = IoctlEvtchnClose(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_EVTCHN_NOTIFY:
        status = IoctlEvtchnNotify(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_EVTCHN_UNMASK:
        status = IoctlEvtchnUnmask(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_EVTCHN_STATUS:
        status = IoctlEvtchnStatus(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

        // gnttab
    case IOCTL_XENIFACE_GNTTAB_GRANT_PAGES:
        status = IoctlGnttabGrantPages(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_GNTTAB_UNGRANT_PAGES:
        status = IoctlGnttabUngrantPages(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES:
        status = IoctlGnttabMapForeignPages(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
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

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
