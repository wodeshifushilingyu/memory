#include "pch.h"
#include "memory.h"
#include "PageVad.h"
#include "hooks.h"
#include "Inject.h"

#define KD_ENUMERATE_DEBUGGING_DEVICES_PATTERN "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\x85\xC0\x78\x40"
#define KD_ENUMERATE_DEBUGGING_DEVICES_MASK "xxx????x????xxxxxx"

#define HVLP_QUERY_APIC_ID_AND_NUMA_NODE_PATTERN "\x48\x8B\x05\x00\x00\x00\x00\x45\x33\xC0\xE8"
#define HVLP_QUERY_APIC_ID_AND_NUMA_NODE_MASK "xxx????xxxx"

#define HVLP_QUERY_APIC_ID_AND_NUMA_NODE_CALL_PATTERN "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x20\x83\x0A\xFF"
#define HVLP_QUERY_APIC_ID_AND_NUMA_NODE_CALL_MASK "xxxx?xxxx?xxxxxxxx"


#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

#define DATA_UNIQUE (0x8392)


INT64(NTAPI* EnumerateDebuggingDevicesOriginal)(PVOID, PVOID);
INT64(__fastcall* HvlpQueryApicIdAndNumaNodeOriginal)(PVOID, PVOID, PVOID);
INT64(__fastcall* HvlpQueryProcessorNodeOriginal)(PVOID, PVOID, PVOID);



BOOL hooks::CheckMask(PCHAR Base,PCHAR Pattern,PCHAR Mask)
{
	//VMPEX
	for (; *Mask; ++Base, ++Pattern, ++Mask) 
	{
		if (*Mask == 'x' && *Base != *Pattern) 
			return FALSE;
	}
	return TRUE;
	//END
}

PVOID hooks::FindPattern(PCHAR Base,DWORD Length,PCHAR Pattern,PCHAR Mask)
{
	//VMPEX
	Length -= (DWORD)strlen(Mask);
	for (DWORD i = 0; i <= Length; ++i) 
	{
		PVOID Addr = &Base[i];
		if (CheckMask((PCHAR)Addr, Pattern, Mask)) 
			return Addr;
	}
	return 0;
	//END
}

PVOID hooks::FindPatternImage(PCHAR Base,PCHAR Pattern,PCHAR Mask) 
{
	//VMPEX
	PVOID Match = 0;
	PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);
	for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) 
	{
		PIMAGE_SECTION_HEADER Section = &Sections[i];
		if (*(PINT)Section->Name == 'EGAP' || memcmp(Section->Name, ".text", 5) == 0) 
		{
			Match = FindPattern(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
			if (Match) 
				break;
		}
	}

	return Match;
	//END
}

PVOID hooks::GetKernelBase() 
{
	//VMPEX
	PVOID KernelBase = NULL;

	ULONG size = NULL;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) 
		return KernelBase;

	auto Modules = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));

	if (!Modules) 
		return KernelBase;

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, Modules, size, 0))) 
	{
		ExFreePool(Modules);
		return KernelBase;
	}

	if (Modules->NumberOfModules > 0) 
		KernelBase = Modules->Modules[0].ImageBase;

	ExFreePool(Modules);
	return KernelBase;
	//END
}

NTSTATUS hooks::Initialize()
{
	//VMP
	PCHAR Base = (PCHAR)GetKernelBase();

	auto xKdEnumerateDebuggingDevicesPattern = skCrypt(KD_ENUMERATE_DEBUGGING_DEVICES_PATTERN);
	auto xKdEnumerateDebuggingDevicesMask = skCrypt(KD_ENUMERATE_DEBUGGING_DEVICES_MASK);
	PBYTE FunctionAddress = (PBYTE)FindPatternImage(Base, xKdEnumerateDebuggingDevicesPattern, xKdEnumerateDebuggingDevicesMask);
	xKdEnumerateDebuggingDevicesPattern.clear();
	xKdEnumerateDebuggingDevicesMask.clear();
	if (!FunctionAddress) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "failed to get xKdEnumerateDebuggingDevices");
		DbgPrint("[+]   failed to get xKdEnumerateDebuggingDevices");
		return STATUS_UNSUCCESSFUL;
	}

	auto HvlpQueryApicIdAndNumaNodePattern = skCrypt(HVLP_QUERY_APIC_ID_AND_NUMA_NODE_PATTERN);
	auto HvlpQueryApicIdAndNumaNodeMask = skCrypt(HVLP_QUERY_APIC_ID_AND_NUMA_NODE_MASK);
	PBYTE HvlpQueryApicIdAndNumaNodeAddress = (PBYTE)FindPatternImage(Base, HvlpQueryApicIdAndNumaNodePattern, HvlpQueryApicIdAndNumaNodeMask);
	HvlpQueryApicIdAndNumaNodePattern.clear();
	HvlpQueryApicIdAndNumaNodeMask.clear();
	if (!HvlpQueryApicIdAndNumaNodeAddress) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "failed to get HvlpQueryApicIdAndNumaNodeAddress");
		DbgPrint("[+]   failed to get HvlpQueryApicIdAndNumaNodeAddress");
		return STATUS_UNSUCCESSFUL;
	}

	auto HvlpQueryApicIdAndNumaNodeCallPattern = skCrypt(HVLP_QUERY_APIC_ID_AND_NUMA_NODE_CALL_PATTERN);
	auto HvlpQueryApicIdAndNumaNodeCallMask = skCrypt(HVLP_QUERY_APIC_ID_AND_NUMA_NODE_CALL_MASK);
	PBYTE HvlpQueryApicIdAndNumaNodeCallAddress = (PBYTE)FindPatternImage(Base, HvlpQueryApicIdAndNumaNodeCallPattern, HvlpQueryApicIdAndNumaNodeCallMask);
	HvlpQueryApicIdAndNumaNodeCallPattern.clear();
	HvlpQueryApicIdAndNumaNodeCallMask.clear();
	if (!HvlpQueryApicIdAndNumaNodeAddress) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "failed to get HvlpQueryApicIdAndNumaNodeCallAddress");
		DbgPrint("[+]   failed to get HvlpQueryApicIdAndNumaNodeCallAddress");
		return STATUS_UNSUCCESSFUL;
	}

	*(PVOID*)&HvlpQueryApicIdAndNumaNodeOriginal = InterlockedExchangePointer((volatile PVOID*)RELATIVE_ADDR(HvlpQueryApicIdAndNumaNodeAddress, 7), (PVOID)hkHvlpQueryApicIdAndNumaNode);
	*(PVOID*)&EnumerateDebuggingDevicesOriginal = InterlockedExchangePointer((volatile PVOID*)RELATIVE_ADDR(FunctionAddress, 7), (PVOID)HvlpQueryApicIdAndNumaNodeCallAddress);


	return 0;
	//END
}


INT64 NTAPI hooks::hkHvlpQueryApicIdAndNumaNode(PVOID data, PINT64 Status, PVOID a3)
{
	//VMPEX
	UNREFERENCED_PARAMETER(a3);
	
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return EnumerateDebuggingDevicesOriginal(data, Status);

	auto myCommunication = reinterpret_cast<PCommunication>(data);
	if(!myCommunication)
		return EnumerateDebuggingDevicesOriginal(data, Status);

	if (myCommunication->Symbol != DATA_UNIQUE)
		return EnumerateDebuggingDevicesOriginal(data, Status);
	
	DbgPrintEx(0,0,"[+]  SafeData.Type %d\n", myCommunication->Type);

	switch (myCommunication->Type)
	{
		case CommunicationType::Initialize:
			return 0x666;
		case CommunicationType::SetVirtualMemory:
			return memory::KeSetVirtualMemory(myCommunication);
		case CommunicationType::ReadMemory:
			return memory::KeReadProcessMemory(myCommunication);
		case CommunicationType::WriteMemory:
			return memory::KeWriteProcessMemory(myCommunication);
		case CommunicationType::Allocate:
			return memory::KeAllocateVirtuaMemory(myCommunication);
		case CommunicationType::FreeAllocate:
			return memory::KeFreeVirtualMemory(myCommunication);
		case CommunicationType::GetModule:
			return memory::KeGetProcessModuleHandle(myCommunication);
		case CommunicationType::PageSetVad:
			return PageVad::RemoveVadRequest(myCommunication);
		case CommunicationType::InjectDll:
			return Inject::InjectDll(myCommunication);
		case CommunicationType::CreatehTread:
			return Inject::UesrCreateHandle(myCommunication);
		case CommunicationType::HideProcessById:
			memory::KeHideProcess(myCommunication);
	}
	*Status = STATUS_NOT_IMPLEMENTED;
	return 0;
	//END
}