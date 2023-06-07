#pragma once
#include <windows.h>
#include <Psapi.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define DATA_UNIQUE (0x8392)

namespace driver
{

	extern DWORD ProcessId;

	NTSTATUS InitializeCallAddress();

	NTSTATUS InitializeDriver();

	NTSTATUS KeSetVirtualMemory(DWORD ProcessId, ULONG64 Address, ULONG64 dwSize);

	NTSTATUS KeReadProcesMemory(DWORD ProcessId, ULONG64 Address, PVOID64 Buffer, ULONG64 dwSize);

	NTSTATUS KeWriteProcessMemory(DWORD ProcessId, ULONG64 Address, PVOID64 Buffer, ULONG64 dwSize);

	NTSTATUS KeAllocateMemory(DWORD ProcessId, ULONG64* Address, ULONG64 dwSize);

	NTSTATUS KeFreeAllocateMemory(DWORD ProcessId, ULONG64 Address);

	NTSTATUS KeGetModuleHandle(DWORD ProcessId, const wchar_t ModuleName[260], ULONG64* Modulehandle);

	NTSTATUS kernel_inject_dll(DWORD ProcessId, PVOID64 DllBuffer, ULONG64 dwSize);

	NTSTATUS kernel_uesr_CreateThread(DWORD ProcessId, PVOID64 Address, PVOID64 Buffer);

	NTSTATUS kernel_hide_processbyid(DWORD ProcessId);
	
	template<typename T = ULONG64>
	T RPM(ULONG64 Address, SIZE_T dwSize = sizeof(T))
	{
		SIZE_T size{};
		T dRet{};
		if (!NT_SUCCESS(KeReadProcesMemory(ProcessId, ULONG64(Address), &dRet, dwSize)))
			return T();
		return dRet;
	}
	template<typename T = ULONG64>
	bool RPM(ULONG64 Address, T* Buffer, SIZE_T dwSize = sizeof(T))
	{
		SIZE_T size{};
		return NT_SUCCESS(KeReadProcesMemory(ProcessId, ULONG64(Address), Buffer, dwSize));
	}
	template<typename T = ULONG64>
	bool WPM(ULONG64 Address, T Buffer, SIZE_T dwSize = sizeof(T))
	{
		SIZE_T size{};
		return NT_SUCCESS(KeWriteProcessMemory(ProcessId, ULONG64(Address), &Buffer, dwSize));
	}
	template<typename T = ULONG64>
	bool WPM(ULONG64 Address, T* Buffer, SIZE_T dwSize = sizeof(T))
	{
		SIZE_T size{};
		return NT_SUCCESS(KeWriteProcessMemory(ProcessId, ULONG64(Address), Buffer, dwSize));
	}
}
