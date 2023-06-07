// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include <iostream>
#include "stdio.h"
#include "bcrypt.h"


#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define DATA_UNIQUE (0x8392)

PVOID(NTAPI* NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(PVOID, PVOID, PVOID, PVOID);

enum CommunicationType
{
	Initialize,
	SetVirtualMemory,
	ReadMemory,
	WriteMemory,
	Allocate,
	FreeAllocate,
	GetModule
};

typedef struct _Communication
{
	ULONG64 Symbol;
	CommunicationType Type;
	DWORD ProcessId;
	PVOID64 Address;
	PVOID64 Buffer;
	ULONG64 dwSize;
	wchar_t ModuleName[260];
}Communication, * POINTER_64 PCommunication;


extern "C" __declspec(dllexport) NTSTATUS __stdcall InitializeCallAddress();
extern "C" __declspec(dllexport) NTSTATUS __stdcall InitializeDriver();
extern "C" __declspec(dllexport) NTSTATUS __stdcall KeSetVirtualMemory(DWORD* ProcessId, ULONG64* Address, ULONG64* dwSize);
extern "C" __declspec(dllexport) NTSTATUS __stdcall KeReadProcesMemory(DWORD* ProcessId, ULONG64* Address, PVOID64* Buffer, ULONG64* dwSize);
extern "C" __declspec(dllexport) NTSTATUS __stdcall KeWriteProcessMemory(DWORD* ProcessId, ULONG64* Address, PVOID64* Buffer, ULONG64* dwSize);
extern "C" __declspec(dllexport) NTSTATUS __stdcall KeAllocateMemory(DWORD* ProcessId, ULONG64* Address, ULONG64* dwSize);
extern "C" __declspec(dllexport) NTSTATUS __stdcall KeFreeAllocateMemory(DWORD* ProcessId, ULONG64* Address);
extern "C" __declspec(dllexport) NTSTATUS __stdcall KeGetModuleHandle(DWORD* ProcessId, char* name, int* len, ULONG64* Modulehandle);







NTSTATUS __stdcall InitializeCallAddress()
{
	auto Module = LoadLibrary((L"ntdll.dll"));
	if (!Module)
		return -1;
	*reinterpret_cast<PVOID*>(&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) = GetProcAddress(Module, ("NtConvertBetweenAuxiliaryCounterAndPerformanceCounter"));
	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)
		return -1;
	return 1;
}

NTSTATUS __stdcall InitializeDriver()
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = Initialize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;

	if (0x666 != NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0)))
		return 0;
	return 1;
}


NTSTATUS __stdcall KeSetVirtualMemory(DWORD* ProcessId, ULONG64* Address, ULONG64* dwSize)
{
	printf("KeSetVirtualMemory Fund  ProcessId [%d] --- Address [%lld] --- dwSize [%lld]\n",*ProcessId,*Address,*dwSize);


	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = SetVirtualMemory;
	Request.ProcessId = *ProcessId;
	Request.Address = PVOID64(*Address);
	Request.dwSize = *dwSize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	if (STATUS_SUCCESS != NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0)))
		return 0;
	return 1;
}

NTSTATUS __stdcall KeReadProcesMemory(DWORD* ProcessId, ULONG64* Address, PVOID64* Buffer, ULONG64* dwSize)
{
	printf("KeReadProcesMemory Fund  ProcessId [%d] --- Address [%lld] --- Buffer [%lld] --- dwSize [%lld]\n", *ProcessId, *Address, Buffer ,*dwSize);
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = ReadMemory;
	Request.ProcessId = *ProcessId;
	Request.Address = PVOID64(*Address);
	Request.Buffer = PVOID64(Buffer);
	Request.dwSize = *dwSize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	if (STATUS_SUCCESS != NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0)))
		return 0;
	return 1;
}

NTSTATUS __stdcall KeWriteProcessMemory(DWORD* ProcessId, ULONG64* Address, PVOID64* Buffer, ULONG64* dwSize)
{
	printf("KeWriteProcessMemory Fund  ProcessId [%d] --- Address [%lld] --- Buffer [%d] --- dwSize [%d]\n", *ProcessId, *Address, Buffer, *dwSize);
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = WriteMemory;
	Request.ProcessId = *ProcessId;
	Request.Address = PVOID64(*Address);
	Request.Buffer = PVOID64(Buffer);
	Request.dwSize = *dwSize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	if (STATUS_SUCCESS != NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0)))
		return 0;
	return 1;
}


NTSTATUS __stdcall KeAllocateMemory(DWORD* ProcessId, ULONG64* Address, ULONG64* dwSize)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = Allocate;
	Request.ProcessId = *ProcessId;
	Request.dwSize = *dwSize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	auto ret = NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
	*Address = ULONG64(Request.Address);


	printf("KeAllocateMemory Func Process [%d] --- dwSize [%d] --- AllocateAddress [%p]\n", *ProcessId, *dwSize, (Request.Address));
	if (STATUS_SUCCESS != ret)
		return 0;
	return 1;
}


NTSTATUS __stdcall KeFreeAllocateMemory(DWORD* ProcessId, ULONG64* Address)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = FreeAllocate;
	Request.ProcessId = *ProcessId;
	Request.Address = PVOID64(*Address);
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	if (STATUS_SUCCESS != NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0)))
		return 0;
	return 1;
}


NTSTATUS __stdcall KeGetModuleHandle(DWORD* ProcessId, char* name, int* len, ULONG64* Modulehandle)
{
	printf("KeGetModuleHandle  %s  len %d\n", name, *len);

	auto hmname = malloc(*len);
	RtlCopyMemory(hmname, name, *len);
	size_t len1 = *len + 1;
	size_t converted = 0;
	wchar_t* WStr;
	WStr = (wchar_t*)malloc(len1 * sizeof(wchar_t));
	mbstowcs_s(&converted, WStr, len1, (char*)hmname, _TRUNCATE);

	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = GetModule;
	Request.ProcessId = *ProcessId;
	RtlCopyMemory(Request.ModuleName, WStr, 260);
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	auto ret = NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
	*Modulehandle = ULONG64(Request.Address);
	free(WStr);
	free(hmname);
	printf("KeGetModuleHandle  %s  len %d    wname %ws   ret %d   %lld  \n", name, *len, WStr, ret, ULONG64(Request.Address));
	if (STATUS_SUCCESS != ret)
		return 0;
	return 1;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		MessageBox(0, L"TEST", L"TEST", 0);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

