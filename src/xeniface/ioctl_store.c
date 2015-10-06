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

static
NTSTATUS
__CaptureUserBuffer(
    __in  PVOID Buffer,
    __in  ULONG Length,
    __out PVOID *CapturedBuffer
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

static
VOID
__FreeCapturedBuffer(
    __in  PVOID CapturedBuffer
    )
{
    if (CapturedBuffer != NULL) {
        ExFreePoolWithTag(CapturedBuffer, XENIFACE_POOL_TAG);
    }
}

static FORCEINLINE
BOOLEAN
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

static FORCEINLINE
ULONG
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

static FORCEINLINE
VOID
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
        XenIfaceDebugPrint(TRACE, "|%s: [%d]=(%d)->\"%s\"\n", Caller, Idx, Len, Ptr);
        Ptr += (Len + 1);
    }
}

DECLSPEC_NOINLINE
NTSTATUS
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
        XenIfaceDebugPrint(TRACE, "(\"%s\")=(%d)\n", Buffer, Length);
        goto done;
    }

    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    XenIfaceDebugPrint(TRACE, "(\"%s\")=(%d)->\"%s\"\n", Buffer, Length, Value);

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

DECLSPEC_NOINLINE
NTSTATUS
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

    XenIfaceDebugPrint(TRACE, "(\"%s\"=\"%s\")\n", Buffer, Value);
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

DECLSPEC_NOINLINE
NTSTATUS
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
        XenIfaceDebugPrint(TRACE, "(\"%s\")=(%d)(%d)\n", Buffer, Length, Count);
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

DECLSPEC_NOINLINE
NTSTATUS
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

    XenIfaceDebugPrint(TRACE, "(\"%s\")\n", Buffer);
    return status;

fail3:
    XenIfaceDebugPrint(ERROR, "Fail3 (\"%s\")\n", Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreSetPermissions(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PXENIFACE_STORE_SET_PERMISSIONS_IN In = (PXENIFACE_STORE_SET_PERMISSIONS_IN)Buffer;
    ULONG Index;
    PCHAR Path;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen < sizeof(XENIFACE_STORE_SET_PERMISSIONS_IN) || OutLen != 0)
        goto fail1;

    if (InLen < sizeof(XENIFACE_STORE_SET_PERMISSIONS_IN) + In->NumberPermissions * sizeof(XENBUS_STORE_PERMISSION))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (In->PathLength == 0 || In->PathLength > XENSTORE_ABS_PATH_MAX)
        goto fail3;

    status = __CaptureUserBuffer(In->Path, In->PathLength, &Path);
    if (!NT_SUCCESS(status))
        goto fail4;

    Path[In->PathLength - 1] = 0;
    XenIfaceDebugPrint(TRACE, "> Path '%s', NumberPermissions %lu\n", Path, In->NumberPermissions);

    for (Index = 0; Index < In->NumberPermissions; Index++) {
        XenIfaceDebugPrint(TRACE, "> %lu: Domain %d, Mask 0x%x\n", Index, In->Permissions[Index].Domain, In->Permissions[Index].Mask);
        if ((In->Permissions[Index].Mask & ~XENIFACE_STORE_ALLOWED_PERMISSIONS) != 0)
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

    __FreeCapturedBuffer(Path);
    return status;

fail6:
    XenIfaceDebugPrint(ERROR, "Fail6\n");
fail5:
    XenIfaceDebugPrint(ERROR, "Fail5\n");
    __FreeCapturedBuffer(Path);
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
IoctlStoreAddWatch(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PXENIFACE_STORE_ADD_WATCH_IN In = (PXENIFACE_STORE_ADD_WATCH_IN)Buffer;
    PXENIFACE_STORE_ADD_WATCH_OUT Out = (PXENIFACE_STORE_ADD_WATCH_OUT)Buffer;
    PCHAR Path;
    PXENIFACE_STORE_CONTEXT Context;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_STORE_ADD_WATCH_IN) || OutLen != sizeof(XENIFACE_STORE_ADD_WATCH_OUT))
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (In->PathLength == 0 || In->PathLength > XENSTORE_ABS_PATH_MAX)
        goto fail2;

    status = __CaptureUserBuffer(In->Path, In->PathLength, &Path);
    if (!NT_SUCCESS(status))
        goto fail3;

    Path[In->PathLength - 1] = 0;

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_STORE_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail4;

    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));

    Context->FileObject = FileObject;

    status = ObReferenceObjectByHandle(In->Event, EVENT_MODIFY_STATE, *ExEventObjectType, UserMode, &Context->Event, NULL);
    if (!NT_SUCCESS(status))
        goto fail5;

    XenIfaceDebugPrint(TRACE, "> Path '%s', Event %p, FO %p\n", Path, In->Event, FileObject);

    status = XENBUS_STORE(WatchAdd,
                          &Fdo->StoreInterface,
                          NULL, // prefix
                          Path,
                          Context->Event,
                          &Context->Watch);

    if (!NT_SUCCESS(status))
        goto fail6;

    __FreeCapturedBuffer(Path);

    ExInterlockedInsertTailList(&Fdo->StoreWatchList, &Context->Entry, &Fdo->StoreWatchLock);

    XenIfaceDebugPrint(TRACE, "< Context %p, Watch %p\n", Context, Context->Watch);

    Out->Context = Context;
    *Info = sizeof(XENIFACE_STORE_ADD_WATCH_OUT);

    return status;

fail6:
    XenIfaceDebugPrint(ERROR, "Fail6\n");
    ObDereferenceObject(Context->Event);
fail5:
    XenIfaceDebugPrint(ERROR, "Fail5\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
fail4:
    XenIfaceDebugPrint(ERROR, "Fail4\n");
    __FreeCapturedBuffer(Path);
fail3:
    XenIfaceDebugPrint(ERROR, "Fail3\n");
fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
StoreFreeWatch(
    __in  PXENIFACE_FDO Fdo,
    __in  PXENIFACE_STORE_CONTEXT Context
    )
{
    NTSTATUS status;

    XenIfaceDebugPrint(TRACE, "Context %p, Watch %p, FO %p\n",
                       Context, Context->Watch, Context->FileObject);

    status = XENBUS_STORE(WatchRemove,
                          &Fdo->StoreInterface,
                          Context->Watch);

    ASSERT(NT_SUCCESS(status)); // this is fatal since we'd leave an active watch without cleaning it up

    ObDereferenceObject(Context->Event);
    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRemoveWatch(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    )
{
    NTSTATUS status;
    PXENIFACE_STORE_REMOVE_WATCH_IN In = (PXENIFACE_STORE_REMOVE_WATCH_IN)Buffer;
    PXENIFACE_STORE_CONTEXT Context = NULL;
    KIRQL Irql;
    PLIST_ENTRY Node;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_STORE_REMOVE_WATCH_IN) || OutLen != 0)
        goto fail1;

    XenIfaceDebugPrint(TRACE, "> Context %p, FO %p\n", In->Context, FileObject);

    KeAcquireSpinLock(&Fdo->StoreWatchLock, &Irql);
    Node = Fdo->StoreWatchList.Flink;
    while (Node->Flink != Fdo->StoreWatchList.Flink) {
        Context = CONTAINING_RECORD(Node, XENIFACE_STORE_CONTEXT, Entry);

        Node = Node->Flink;
        if (Context != In->Context || Context->FileObject != FileObject)
            continue;

        RemoveEntryList(&Context->Entry);
        break;
    }
    KeReleaseSpinLock(&Fdo->StoreWatchLock, Irql);

    status = STATUS_NOT_FOUND;
    if (Context == NULL || Context != In->Context)
        goto fail2;

    StoreFreeWatch(Fdo, Context);

    return STATUS_SUCCESS;

fail2:
    XenIfaceDebugPrint(ERROR, "Fail2\n");
fail1:
    XenIfaceDebugPrint(ERROR, "Fail1 (%08x)\n", status);
    return status;
}
