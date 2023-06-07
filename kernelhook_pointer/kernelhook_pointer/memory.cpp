#include "pch.h"
#include "memory.h"

PEPROCESS memory::TargetProcess{};

NTSTATUS memory::KeSetVirtualMemory(PCommunication buf)
{
	//VMPEX
	if (buf == nullptr)
		return 0x1000;
	if (buf->ProcessId == 0 || buf->Address == 0 || buf->dwSize == 0)
		return 0x1001;

	HANDLE hProcess{};
	OBJECT_ATTRIBUTES Object{};
	ULONG64 ZwProtectVirtualMemory{};
	UNICODE_STRING RoutineName{};
	DWORD OldProtect{};
	InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	CLIENT_ID Cid{};
	Cid.UniqueProcess = HANDLE(buf->ProcessId);

	auto status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &Cid);
	if (status != STATUS_SUCCESS)
		return status;
	RtlInitUnicodeString(&RoutineName, L"ZwProtectVirtualMemory");
	ZwProtectVirtualMemory = (ULONG64)MmGetSystemRoutineAddress(&RoutineName);
	if (ZwProtectVirtualMemory == 0)
		return 0x10002;
	status = ((NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))(ZwProtectVirtualMemory))(hProcess, &buf->Address, &buf->dwSize, PAGE_EXECUTE_READWRITE, &OldProtect);
	if (status != STATUS_SUCCESS)
	{
		ZwClose(hProcess);
		return status;
	}
	ZwClose(hProcess);
	return status;
	//END
}

BOOL memory::IsUserAddress(PVOID Address)
{
	//VMPEX
	return reinterpret_cast<SIZE_T>(Address) < (static_cast<SIZE_T>(1) << (8 * sizeof(SIZE_T) - 1));
	//END
}

BOOL memory::IsKernelAddress(PVOID Address)
{
	//VMPEX
	return reinterpret_cast<SIZE_T>(Address) >= (static_cast<SIZE_T>(1) << (8 * sizeof(SIZE_T) - 1));
	//END
}

NTSTATUS memory::KeReadWriteProcessMemory(PCommunication buf, DWORD Types)
{
	//VMPEX
	if (buf == nullptr)
		return 0x1000;
	if (buf->ProcessId == 0 || buf->Address == nullptr || buf->dwSize == NULL || buf->Buffer == nullptr)
		return 0x1001;
	if (IsUserAddress(buf->Address) == FALSE)
		return FALSE;

	SIZE_T result{};
	auto status = PsLookupProcessByProcessId((HANDLE)buf->ProcessId, &TargetProcess);
	if (status != STATUS_SUCCESS)
		return status;

	if (Types == 16)
		status = MmCopyVirtualMemory(TargetProcess, buf->Address, IoGetCurrentProcess(), buf->Buffer, buf->dwSize, KernelMode, &result);
	else if (Types == 32)
		status = MmCopyVirtualMemory(IoGetCurrentProcess(), buf->Buffer, TargetProcess, buf->Address, buf->dwSize, KernelMode, &result);

	if (status != STATUS_SUCCESS)
	{
		ObDereferenceObject(TargetProcess);
		return status;
	}
	ObDereferenceObject(TargetProcess);
	return status;
	//END
}

NTSTATUS memory::KeReadProcessMemory(PCommunication buf)
{
	//VMPEX
	return KeReadWriteProcessMemory(buf, 16);
	//END
}

NTSTATUS memory::KeWriteProcessMemory(PCommunication buf)
{
	//VMPEX
	return KeReadWriteProcessMemory(buf, 32);
	//END
}

NTSTATUS memory::KeAllocateVirtuaMemory(PCommunication buf)
{
	//VMPEX
	if (buf == nullptr)
		return 0x1000;
	if (buf->ProcessId == 0 || buf->dwSize == NULL)
		return 0x1001;

	OBJECT_ATTRIBUTES Object{};
	InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE hProcess{};
	CLIENT_ID Cid{};
	Cid.UniqueProcess = HANDLE(buf->ProcessId);
	auto status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &Cid);
	if (status != STATUS_SUCCESS)
	{
		DbgPrintEx(0, 0, "status %X\n", status);
		return status;
	}
	status = ZwAllocateVirtualMemory(hProcess, &buf->Address, 0, &buf->dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (status != STATUS_SUCCESS)
	{
		DbgPrintEx(0, 0, "status %X \n", status);
		ZwClose(hProcess);
		return status;
	}
	ZwClose(hProcess);
	return status;
	//END
}

NTSTATUS memory::KeFreeVirtualMemory(PCommunication buf)
{
	//VMPEX
	if (buf == nullptr)
		return 0x1000;
	if (buf->ProcessId == 0 || buf->Address == 0)
		return 0x1001;


	OBJECT_ATTRIBUTES Object{};
	InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE hProcess{};
	CLIENT_ID Cid{};
	Cid.UniqueProcess = HANDLE(buf->ProcessId);

	auto status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &Cid);
	if (status != STATUS_SUCCESS)
		return status;

	status = ZwFreeVirtualMemory(hProcess, &buf->Address, &buf->dwSize, MEM_RELEASE);
	if (status != STATUS_SUCCESS)
	{
		ZwClose(hProcess);
		return status;
	}
	ZwClose(hProcess);
	return status;
	//END
}

void* get_system_module_base(const char* module_name)
{
	//VMPEX
	if (module_name == nullptr) return nullptr;

	unsigned unsigned long count = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, count, &count);
	if (count == 0) return nullptr;

	const unsigned long tag = 'VMON';
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, count, tag);
	if (modules == nullptr) return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, count, &count);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(modules, tag);
		return nullptr;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	void* module_base = nullptr;
	for (unsigned long i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((const char*)module[i].FullPathName, module_name) == 0)
		{
			module_base = module[i].ImageBase;
			break;
		}
	}

	ExFreePoolWithTag(modules, tag);
	return module_base;
	//END
}

void* get_system_module_export(const char* module_name, const char* routine_name)
{
	//VMPEX
	void* base = get_system_module_base(module_name);
	if (base == nullptr) return nullptr;
	else return RtlFindExportedRoutineByName(base, routine_name);
	//END
}

ULONG64 GetModuleHandleFromProcessPEB_32(_PEB32* Peb, PUNICODE_STRING szDllName)
{
	//VMPEX
	//_PEB_LDR_DATA* pLdrData = NULL;
	_PEB_LDR_DATA32* pLdrData = NULL;
	_LDR_DATA_TABLE_ENTRY32* pLdrDataEntry = NULL;
	LIST_ENTRY32* TempListItem = NULL;
	ULONG64 DllBase = 0;
	UNICODE_STRING name{};
	pLdrData = (_PEB_LDR_DATA32*)UlongToPtr(Peb->Ldr);
	TempListItem = &pLdrData->InLoadOrderModuleList;

	for (TempListItem = (LIST_ENTRY32*)UlongToPtr(TempListItem->Flink); TempListItem != &pLdrData->InLoadOrderModuleList; TempListItem = (LIST_ENTRY32*)UlongToPtr(TempListItem->Flink))
	{
		pLdrDataEntry = (_LDR_DATA_TABLE_ENTRY32*)TempListItem;
		if (pLdrDataEntry->BaseDllName.Buffer)
		{
			RtlInitUnicodeString(&name, (wchar_t*)UlongToPtr(pLdrDataEntry->BaseDllName.Buffer));
			if (RtlEqualUnicodeString(&name, szDllName, TRUE) == TRUE)
			{
				DllBase = (ULONG64)pLdrDataEntry->DllBase;
				break;
			}
		}
	}
	return DllBase;
	//END
}

ULONG64 GetModuleHandleFromProcessPEB(_PEB64* Peb, PUNICODE_STRING szDllName)
{
	//VMPEX
	_PEB_LDR_DATA* pLdrData = NULL;
	_LDR_DATA_TABLE_ENTRY* pLdrDataEntry = NULL;
	PLIST_ENTRY TempListItem = NULL;
	ULONG64 DllBase = 0;
	pLdrData = (_PEB_LDR_DATA*)Peb->Ldr;
	TempListItem = &pLdrData->InLoadOrderModuleList;

	for (TempListItem = TempListItem->Flink; TempListItem != &pLdrData->InLoadOrderModuleList; TempListItem = TempListItem->Flink)
	{
		pLdrDataEntry = (_LDR_DATA_TABLE_ENTRY*)TempListItem;
		if (pLdrDataEntry->BaseDllName.Buffer)
		{
			if (RtlEqualUnicodeString(&pLdrDataEntry->BaseDllName, szDllName, TRUE) == TRUE)
			{
				DllBase = (ULONG64)pLdrDataEntry->DllBase;
				break;
			}
		}
	}
	return DllBase;
	//END
}

NTSTATUS memory::KeGetProcessModuleHandle(PCommunication buf)
{
	//VMPEX
	if (buf == nullptr)
		return 0x1000;
	if (buf->ProcessId == 0)
		return 0x1001;

	KAPC_STATE stack{};
	PEPROCESS Wow64Process{};
	UNICODE_STRING str{};
	ULONG64 PsGetProcessWow64Process{}, PsGetProcessPeb{};
	wchar_t name[260];
	ULONG64 result{};

	using _PsGetCurrentProcessWow64Process = PEPROCESS(NTAPI*)();

	auto PsGetCurrentProcessWow64Process = reinterpret_cast<_PsGetCurrentProcessWow64Process>(get_system_module_export("\\SystemRoot\\system32\\ntoskrnl.exe", "PsGetCurrentProcessWow64Process"));

	if (PsGetCurrentProcessWow64Process)
	{
		auto status = PsLookupProcessByProcessId((HANDLE)buf->ProcessId, &TargetProcess);
		if (status != STATUS_SUCCESS)
			return status;

		KeStackAttachProcess(TargetProcess, &stack);
		Wow64Process = PsGetCurrentProcessWow64Process();
		KeUnstackDetachProcess(&stack);
		ObDereferenceObject(TargetProcess);
		if (Wow64Process)
		{
			status = PsLookupProcessByProcessId((HANDLE)buf->ProcessId, &TargetProcess);
			if (!NT_SUCCESS(status))
				return status;
			RtlInitUnicodeString(&str, L"PsGetProcessWow64Process");
			PsGetProcessWow64Process = (ULONG64)MmGetSystemRoutineAddress(&str);
			if (PsGetProcessWow64Process == 0)
			{
				ObDereferenceObject(TargetProcess);
				return -1;
			}
			memcpy(name, buf->ModuleName, sizeof(name));
			RtlInitUnicodeString(&str, name);
			KeStackAttachProcess(TargetProcess, &stack);
			_PEB32* Peb = ((_PEB32 * (*)(PEPROCESS))(PsGetProcessWow64Process))(TargetProcess);
			if (Peb != nullptr)
			{
				result = GetModuleHandleFromProcessPEB_32(Peb, &str);
			}
			KeUnstackDetachProcess(&stack);
			if (result != 0)
			{
				buf->Address = (PVOID)result;
				ObDereferenceObject(TargetProcess);
				return 0;
			}

		}
		else
		{
			status = PsLookupProcessByProcessId((HANDLE)buf->ProcessId, &TargetProcess);
			if (!NT_SUCCESS(status))
				return -1;
			RtlInitUnicodeString(&str, L"PsGetProcessPeb");
			PsGetProcessPeb = (ULONG64)MmGetSystemRoutineAddress(&str);
			if (PsGetProcessPeb == 0)
			{
				ObDereferenceObject(TargetProcess);
				return -1;
			}
			memcpy(name, buf->ModuleName, sizeof(name));
			RtlInitUnicodeString(&str, name);
			KeStackAttachProcess(TargetProcess, &stack);
			_PEB64* Peb = ((_PEB64 * (*)(PEPROCESS))(PsGetProcessPeb))(TargetProcess);
			if (Peb != nullptr)
			{
				result = GetModuleHandleFromProcessPEB(Peb, &str);
			}
			KeUnstackDetachProcess(&stack);
			if (result != 0)
			{
				buf->Address = (PVOID)result;
				ObDereferenceObject(TargetProcess);
				return 0;
			}
		}


	}
	if (TargetProcess)
		ObDereferenceObject(TargetProcess);
	return -1;
	//END


	
}

NTSTATUS memory::KeHideProcess(PCommunication buf)
{

	//DbgBreakPoint();

	PEPROCESS HideProcess{};
	auto status = PsLookupProcessByProcessId(HANDLE(buf->ProcessId), &HideProcess);
	if (!NT_SUCCESS(status))
		return -1;

	DWORD ProcessIdOffset{};

	for (size_t i = 0; i < 0x1000; i++)
	{
		auto HideProcessIdAddress = ((ULONG64)(HideProcess) + i);

		__try
		{
			auto pid = *(PVOID*)HideProcessIdAddress;
			if (pid == PVOID(buf->ProcessId))
			{
				ProcessIdOffset = i;
				break;
			}
		}
		__except (1)
		{
			ObDereferenceObject(HideProcess);
			return -1;
		}

	}
	__try
	{
		*(PVOID*)((ULONG64)(HideProcess)+ProcessIdOffset) = 0;
	}
	__except (1)
	{
		return -1;
		ObDereferenceObject(HideProcess);
	}
	ObDereferenceObject(HideProcess);
	return 0;
}




