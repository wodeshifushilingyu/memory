#pragma once
namespace hide
{
	NTSTATUS GetDriverObjectByName(PDRIVER_OBJECT* DriverObject, WCHAR* DriverName);
	BOOLEAN SupportSEH(PDRIVER_OBJECT DriverObject);
	PVOID GetMiProcessLoaderEntry();
	void DriverReinitialize(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count);
	NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject);
}
