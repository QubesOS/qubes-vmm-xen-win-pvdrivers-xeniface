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
        XenIfaceDebugPrint(INFO, "|%s: (\"%s\")=(%d)\n", __FUNCTION__, Buffer, Length);
        goto done;
    }

    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    XenIfaceDebugPrint(INFO, "|%s: (\"%s\")=(%d)->\"%s\"\n", __FUNCTION__, Buffer, Length, Value);

    RtlCopyMemory(Buffer, Value, Length);
    Buffer[Length - 1] = 0;
    status = STATUS_SUCCESS;

done:
    *Info = (ULONG_PTR)Length;
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
    return status;

fail4:
    XenIfaceDebugPrint(ERROR, "|%s: Fail4 (\"%s\")=(%d < %d)\n", __FUNCTION__, Buffer, OutLen, Length);
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
fail3:
    XenIfaceDebugPrint(ERROR, "|%s: Fail3 (\"%s\")\n", __FUNCTION__, Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "|%s: Fail2\n", __FUNCTION__);
fail1:
    XenIfaceDebugPrint(ERROR, "|%s: Fail1 (%08x)\n", __FUNCTION__, status);
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

    XenIfaceDebugPrint(INFO, "|%s: (\"%s\"=\"%s\")\n", __FUNCTION__, Buffer, Value);
    return status;

fail4:
    XenIfaceDebugPrint(ERROR, "|%s: Fail4 (\"%s\")\n", __FUNCTION__, Value);
fail3:
    XenIfaceDebugPrint(ERROR, "|%s: Fail3 (\"%s\")\n", __FUNCTION__, Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "|%s: Fail2\n", __FUNCTION__);
fail1:
    XenIfaceDebugPrint(ERROR, "|%s: Fail1 (%08x)\n", __FUNCTION__, status);
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
        XenIfaceDebugPrint(INFO, "|%s: (\"%s\")=(%d)(%d)\n", __FUNCTION__, Buffer, Length, Count);
        goto done;
    }

    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    XenIfaceDebugPrint(INFO, "|%s: (\"%s\")=(%d)(%d)\n", __FUNCTION__, Buffer, Length, Count);
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
    XenIfaceDebugPrint(ERROR, "|%s: Fail4 (\"%s\")=(%d < %d)\n", __FUNCTION__, Buffer, OutLen, Length);
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
fail3:
    XenIfaceDebugPrint(ERROR, "|%s: Fail3 (\"%s\")\n", __FUNCTION__, Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "|%s: Fail2\n", __FUNCTION__);
fail1:
    XenIfaceDebugPrint(ERROR, "|%s: Fail1 (%08x)\n", __FUNCTION__, status);
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

    XenIfaceDebugPrint(INFO, "|%s: (\"%s\")\n", __FUNCTION__, Buffer);
    return status;

fail3:
    XenIfaceDebugPrint(ERROR, "|%s: Fail3 (\"%s\")\n", __FUNCTION__, Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "|%s: Fail2\n", __FUNCTION__);
fail1:
    XenIfaceDebugPrint(ERROR, "|%s: Fail1 (%08x)\n", __FUNCTION__, status);
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
    XENIFACE_EVTCHN_CONTEXT *Ctx = (XENIFACE_EVTCHN_CONTEXT *)Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);
    ASSERT(Context != NULL);

    XenIfaceDebugPrint(TRACE, "Channel %p, LocalPort %d, IRQL %d\n", Ctx->Channel, Ctx->LocalPort, KeGetCurrentIrql());
    KeSetEvent(Ctx->Event, 0, FALSE);
}

_Function_class_(KSERVICE_ROUTINE)
_IRQL_requires_(HIGH_LEVEL)
_IRQL_requires_same_
static DECLSPEC_NOINLINE
BOOLEAN
EvtchnCallback(
    __in     struct _KINTERRUPT *Interrupt,
    __in_opt PVOID Argument
    )
{
    XENIFACE_EVTCHN_CONTEXT *Context = (XENIFACE_EVTCHN_CONTEXT *)Argument;

    UNREFERENCED_PARAMETER(Interrupt);
    ASSERT(Context != NULL);

    XenIfaceDebugPrint(INFO, "Channel %p, LocalPort %d, IRQL %d\n", Context->Channel, Context->LocalPort, KeGetCurrentIrql());

    // we're running at high irql, queue a dpc to signal the event
    KeInsertQueueDpc(&Context->Dpc, NULL, NULL);

    return TRUE;
}

static
VOID
EvtchnFree(
    __in PXENIFACE_FDO Fdo,
    __in XENIFACE_EVTCHN_CONTEXT *Context
    )
{
    XenIfaceDebugPrint(INFO, "LocalPort %d, Process %p\n", Context->LocalPort, Context->Process);
    XENBUS_EVTCHN(Close, &Fdo->EvtchnInterface, Context->Channel);
    ObDereferenceObject(Context->Event);
    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

// Process creation/destruction notify routine.
// Used for cleaning up of allocated event channels.
// Runs at PASSIVE_LEVEL and if Create==FALSE, in the context of the process being destroyed.
VOID
EvtchnProcessNotify(
    __in HANDLE ParentId,
    __in HANDLE ProcessId,
    __in BOOLEAN Create
    )
{
    PEPROCESS CurrentProcess;
    PLIST_ENTRY Node;
    XENIFACE_EVTCHN_CONTEXT *Record;
    KIRQL Irql;

    UNREFERENCED_PARAMETER(ParentId);
    UNREFERENCED_PARAMETER(ProcessId);

    // we're only interested in process destruction for cleanup purposes
    if (Create)
        return;

    CurrentProcess = PsGetCurrentProcess();

    // Walk the list, find everything that's allocated by this process and still not freed.
    KeAcquireSpinLock(&FdoGlobal->EvtchnLock, &Irql);
    Node = FdoGlobal->EvtchnList.Flink;
    while (Node->Flink != FdoGlobal->EvtchnList.Flink) {
        Record = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);

        Node = Node->Flink;
        if (Record->Process != CurrentProcess)
            continue;

        XenIfaceDebugPrint(INFO, "Process %p\n", CurrentProcess);
        RemoveEntryList(&Record->Entry);
        EvtchnFree(FdoGlobal, Record);
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
    EVTCHN_BIND_UNBOUND_PORT_IN *In = (EVTCHN_BIND_UNBOUND_PORT_IN *)Buffer;
    EVTCHN_BIND_UNBOUND_PORT_OUT *Out = (EVTCHN_BIND_UNBOUND_PORT_OUT *)Buffer;
    XENIFACE_EVTCHN_CONTEXT *Context;
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

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    InsertTailList(&Fdo->EvtchnList, &Context->Entry);
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    KeInitializeDpc(&Context->Dpc, EvtchnDpc, Context);

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
    EVTCHN_BIND_INTERDOMAIN_IN *In = (EVTCHN_BIND_INTERDOMAIN_IN *)Buffer;
    EVTCHN_BIND_INTERDOMAIN_OUT *Out = (EVTCHN_BIND_INTERDOMAIN_OUT *)Buffer;
    XENIFACE_EVTCHN_CONTEXT *Context;
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

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    InsertTailList(&Fdo->EvtchnList, &Context->Entry);
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    KeInitializeDpc(&Context->Dpc, EvtchnDpc, Context);

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
    EVTCHN_CLOSE_IN *In = (EVTCHN_CLOSE_IN *)Buffer;
    XENIFACE_EVTCHN_CONTEXT *Record, *Found = NULL;
    PLIST_ENTRY Node;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(EVTCHN_CLOSE_IN) || OutLen != 0)
        goto fail1;

    XenIfaceDebugPrint(INFO, "(LocalPort %d)\n", In->LocalPort);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    Node = Fdo->EvtchnList.Flink;
    while (Node->Flink != Fdo->EvtchnList.Flink) {
        Record = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);

        Node = Node->Flink;
        if (Record->LocalPort != In->LocalPort)
            continue;

        RemoveEntryList(&Record->Entry);
        Found = Record;
    }
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    status = STATUS_INVALID_PARAMETER;
    if (Found == NULL)
        goto fail2;

    XenIfaceDebugPrint(INFO, "Context %p\n", Found);

    EvtchnFree(Fdo, Found);

    return STATUS_SUCCESS;

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
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
    EVTCHN_NOTIFY_IN *In = (EVTCHN_NOTIFY_IN *)Buffer;
    XENIFACE_EVTCHN_CONTEXT *Record, *Found = NULL;
    PLIST_ENTRY Node;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(EVTCHN_NOTIFY_IN) || OutLen != 0)
        goto fail1;

    XenIfaceDebugPrint(INFO, "(LocalPort %d)\n", In->LocalPort);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    Node = Fdo->EvtchnList.Flink;
    while (Node->Flink != Fdo->EvtchnList.Flink) {
        Record = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);

        Node = Node->Flink;
        if (Record->LocalPort != In->LocalPort)
            continue;

        Found = Record;
    }
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    status = STATUS_INVALID_PARAMETER;
    if (Found == NULL)
        goto fail2;

    XenIfaceDebugPrint(INFO, "Context %p\n", Found);

    status = STATUS_ACCESS_DENIED;
    if (Found->Process != PsGetCurrentProcess())
        goto fail3;

    XENBUS_EVTCHN(Send, &Fdo->EvtchnInterface, Found->Channel);

    return STATUS_SUCCESS;

fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");
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

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

done:

    Irp->IoStatus.Status = status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
