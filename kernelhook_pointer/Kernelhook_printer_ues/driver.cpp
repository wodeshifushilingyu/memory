#include "pch.h"
#include "driver.h"




PVOID(NTAPI* NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(PVOID, PVOID, PVOID, PVOID);

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
	PVOID64 Address;
	PVOID64 Buffer;
	ULONG64 dwSize;
	wchar_t ModuleName[260];
	PVOID64 DllBuffer;
}Communication, * POINTER_64 PCommunication;






NTSTATUS driver::InitializeCallAddress()
{
	auto Module = LoadLibrary((L"ntdll.dll"));
	if (!Module)
		return -1;
	*reinterpret_cast<PVOID*>(&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) = GetProcAddress(Module, ("NtConvertBetweenAuxiliaryCounterAndPerformanceCounter"));
	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)
		return -1;
	return 0;
}

NTSTATUS driver::InitializeDriver()
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = Initialize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	return NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
}

NTSTATUS driver::KeSetVirtualMemory(DWORD ProcessId,ULONG64 Address,ULONG64 dwSize)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = SetVirtualMemory;
	Request.ProcessId = ProcessId;
	Request.Address = PVOID64(Address);
	Request.dwSize = dwSize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	return NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
}

NTSTATUS driver::KeReadProcesMemory(DWORD ProcessId, ULONG64 Address, PVOID64 Buffer, ULONG64 dwSize)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = ReadMemory;
	Request.ProcessId = ProcessId;
	Request.Address = PVOID64(Address);
	Request.Buffer = PVOID64(Buffer);
	Request.dwSize = dwSize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	return NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
}

NTSTATUS driver::KeWriteProcessMemory(DWORD ProcessId, ULONG64 Address, PVOID64 Buffer, ULONG64 dwSize)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = WriteMemory;
	Request.ProcessId = ProcessId;
	Request.Address = PVOID64(Address);
	Request.Buffer = PVOID64(Buffer);
	Request.dwSize = dwSize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	return NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
}

NTSTATUS driver::KeAllocateMemory(DWORD ProcessId, ULONG64* Address, ULONG64 dwSize)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = Allocate;
	Request.ProcessId = ProcessId;
	Request.dwSize = dwSize;
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	auto ret = NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
	*Address = ULONG64(Request.Address);
	return ret;
}


NTSTATUS driver::KeFreeAllocateMemory(DWORD ProcessId, ULONG64 Address)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = FreeAllocate;
	Request.ProcessId = ProcessId;
	Request.Address = PVOID64(Address);
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	return NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
}


NTSTATUS driver::KeGetModuleHandle(DWORD ProcessId, const wchar_t ModuleName[260],ULONG64* Modulehandle)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = GetModule;
	Request.ProcessId = ProcessId;
	RtlCopyMemory(Request.ModuleName, ModuleName, 260);
	auto RequestPtr = &Request;
	auto Status = 0ULL;
	auto ret = NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
	*Modulehandle = ULONG64(Request.Address);
	return ret;
}

NTSTATUS driver::kernel_inject_dll(DWORD ProcessId, PVOID64 DllBuffer, ULONG64 dwSize)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = InjectDll;
	Request.ProcessId = ProcessId;
	Request.Buffer = DllBuffer;
	Request.dwSize = dwSize;

	auto RequestPtr = &Request;
	auto Status = 0ULL;
	auto ret = NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
	return ret;
}

NTSTATUS driver::kernel_uesr_CreateThread(DWORD ProcessId, PVOID64 Address,PVOID64 Buffer)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = CreatehTread;
	Request.ProcessId = ProcessId;
	Request.Address = Address;
	Request.Buffer = Buffer;

	auto RequestPtr = &Request;
	auto Status = 0ULL;
	auto ret = NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
	return ret;
}


NTSTATUS driver::kernel_hide_processbyid(DWORD ProcessId)
{
	Communication Request{};
	Request.Symbol = DATA_UNIQUE;
	Request.Type = HideProcessById;
	Request.ProcessId = ProcessId;

	auto RequestPtr = &Request;
	auto Status = 0ULL;
	auto ret = NTSTATUS(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0));
	return ret;
}