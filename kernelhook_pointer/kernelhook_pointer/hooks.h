#pragma once
namespace hooks
{
	BOOL CheckMask(PCHAR Base, PCHAR Pattern, PCHAR Mask);

	PVOID FindPattern(PCHAR Base, DWORD Length, PCHAR Pattern, PCHAR Mask);

	PVOID FindPatternImage(PCHAR Base, PCHAR Pattern, PCHAR Mask);
	
	PVOID GetKernelBase();

	NTSTATUS Initialize();

	INT64 hkHvlpQueryApicIdAndNumaNode(PVOID data, PINT64 Status, PVOID a3);
}

