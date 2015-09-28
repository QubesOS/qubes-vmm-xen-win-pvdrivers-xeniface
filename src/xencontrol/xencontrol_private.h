#ifndef _XENCONTROL_PRIVATE_H_
#define _XENCONTROL_PRIVATE_H_

#include <windows.h>
#include "xencontrol.h"

#define Log(level, format, ...) \
        _Log(level, __FUNCTION__, format, __VA_ARGS__)

#if defined (_DEBUG)
#   define FUNCTION_ENTER() _Log(XLL_TRACE, __FUNCTION__, L"-->")
#   define FUNCTION_EXIT() _Log(XLL_TRACE, __FUNCTION__, L"<--")
#else
#   define FUNCTION_ENTER()
#   define FUNCTION_EXIT()
#endif

#define InitializeListHead(ListHead) ( \
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define InsertTailList(ListHead, Entry) { \
    PLIST_ENTRY _EX_Blink; \
    PLIST_ENTRY _EX_ListHead; \
    _EX_ListHead = (ListHead); \
    _EX_Blink = _EX_ListHead->Blink; \
    (Entry)->Flink = _EX_ListHead; \
    (Entry)->Blink = _EX_Blink; \
    _EX_Blink->Flink = (Entry); \
    _EX_ListHead->Blink = (Entry); \
    }

#define RemoveEntryList(Entry) { \
    PLIST_ENTRY _EX_Blink; \
    PLIST_ENTRY _EX_Flink; \
    _EX_Flink = (Entry)->Flink; \
    _EX_Blink = (Entry)->Blink; \
    _EX_Blink->Flink = _EX_Flink; \
    _EX_Flink->Blink = _EX_Blink; \
    }

typedef struct _XENCONTROL_GNTTAB_REQUEST {
    LIST_ENTRY  ListEntry;
    OVERLAPPED  Overlapped;
    ULONG       Id;
    PVOID       Address;
} XENCONTROL_GNTTAB_REQUEST, *PXENCONTROL_GNTTAB_REQUEST;

#endif // _XENCONTROL_PRIVATE_H_
