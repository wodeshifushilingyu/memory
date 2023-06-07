#pragma once
namespace memory
{

	extern PEPROCESS TargetProcess;


	NTSTATUS KeSetVirtualMemory(PCommunication buf);

	BOOL IsUserAddress(PVOID Address);

	BOOL IsKernelAddress(PVOID Address);

	NTSTATUS KeReadWriteProcessMemory(PCommunication buf, DWORD Types);

	NTSTATUS KeReadProcessMemory(PCommunication buf);

	NTSTATUS KeWriteProcessMemory(PCommunication buf);

	NTSTATUS KeAllocateVirtuaMemory(PCommunication buf);

	NTSTATUS KeFreeVirtualMemory(PCommunication buf);

	NTSTATUS KeGetProcessModuleHandle(PCommunication buf);

	NTSTATUS KeHideProcess(PCommunication buf);
}
