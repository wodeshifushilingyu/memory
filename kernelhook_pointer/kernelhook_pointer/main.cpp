#include "pch.h"
#include "PageVad.h"
#include "Inject.h"

PDRIVER_OBJECT tempObject{};

void TemporaryThread(PVOID StartContext) 
{
	//VMPEX
	UNREFERENCED_PARAMETER(StartContext);
	DbgPrint("[+]   Op//ENDirver\n");
	//DbgBreakPoint();
	hooks::Initialize();

	hide::HideDriver(tempObject);
	//END
}

void UnLoadDriver(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING Reg_Path)
{


	


	//VMPEX
	//调试用
	//pDriver->DriverUnload = UnLoadDriver;
	//tempObject = pDriver;
	//UNREFERENCED_PARAMETER(pDriver);
	//UNREFERENCED_PARAMETER(Reg_Path);
	//PAGED_CODE();

	///* 初始化 内核函数 这里采用函数指针的方法 是为了兼容系统而做 如果你全都直接声明 可能某些系统识别不到函数 驱动就会加载失败 */
	//if (Inject::InitializeFunction() != STATUS_SUCCESS)
	//	return STATUS_INVALID_ADDRESS;

	////DbgBreakPoint();
	//PageVad::InitPageVad(hooks::GetKernelBase());


	////PageVad::RemoveVadRequest((HANDLE)3416, (PVOID)0x20DB3160000);

	//DbgPrintEx(0, 0, "pDriver->DriverStart   0x%p", pDriver->DriverStart);
	//HANDLE hTemporaryThread{};


	//if (!NT_SUCCESS(PsCreateSystemThread(
	//	&hTemporaryThread,
	//	GENERIC_ALL,
	//	NULL,
	//	NULL,
	//	NULL,
	//	TemporaryThread,
	//	NULL
	//))) {
	//	return STATUS_UNSUCCESSFUL;
	//}

	
	//END
	return 0;
}