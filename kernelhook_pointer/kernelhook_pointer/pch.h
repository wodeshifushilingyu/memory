#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "minwindef.h"
#include "ntimage.h"
#include "NtApi.h"
#include "skCrypter.h"



#include "hooks.h"
#include "hide.h"


//#define _VMPROTECT
//
//#ifdef _KERNEL_MODE
//
//#include "VMProtectDDK.h"
//
//#ifdef _VMPROTECT
//
//#define VMP VMProtectBegin(__FUNCTION__);
//#define VMPEX VMProtectBeginUltra(__FUNCTION__);
//#define END VMProtectEnd();
//
//#else
//
//#endif
//
//
//#else
//#include "VMProtectSDK.h"
//
//#endif


enum CommunicationType
{
	Initialize,
	SetVirtualMemory,
	ReadMemory,
	WriteMemory,
	Allocate,
	FreeAllocate,
	GetModule,
	PageSetVad,
	InjectDll,
	CreatehTread,
	HideProcessById

};

typedef struct _Communication
{
	ULONG64 Symbol;
	CommunicationType Type;
	DWORD ProcessId;
	PVOID Address;
	PVOID Buffer;
	SIZE_T dwSize;
	wchar_t ModuleName[260];
	PVOID DllBuffer;

}Communication,* PCommunication;