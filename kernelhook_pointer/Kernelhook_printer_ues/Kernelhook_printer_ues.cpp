// Kernelhook_printer_ues.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "pch.h"

#include "driver.h"

#include <time.h>
#include "ShellCode.h"
#pragma comment(lib,"winmm.lib")



HWND g_GameWindows{};

DWORD driver::ProcessId{};

int main()
{
	driver::ProcessId = 0x39b4;

	auto status = driver::InitializeCallAddress();

	status = driver::InitializeDriver();
	if (status != 0x666)
		printf("InitializeDriver  0x%X\n", status);
	


	printf("请输入pid:");

	std::cin >> driver::ProcessId;

	driver::kernel_hide_processbyid(driver::ProcessId);

	ULONG64 DllAddress{}, ShellCodeAddress{}, CallShellCode{};

	

	//printf("%X\n", status);

	//FILE* iFile = nullptr;
	//size_t filelen = 0;
	//unsigned char* filebuf = 0;

	////auto err = fopen_s(&iFile, ".\\Hell Let Loose Dll.dll", "rb");
	//auto err = fopen_s(&iFile, "C:\\Users\\YangYe\\Desktop\\x86.dll", "rb");

	//printf("err %d\n", err);

	//if (err == 0)
	//{
	//	fseek(iFile, 0, SEEK_END);
	//	filelen = ftell(iFile);
	//	fseek(iFile, 0, SEEK_SET);
	//	filebuf = new unsigned char[filelen] {};
	//	if (!filebuf)
	//		return false;
	//	fread(filebuf, 1, filelen, iFile);
	//	fclose(iFile);
	//}

	//driver::KeAllocateMemory(driver::ProcessId, &DllAddress, filelen);

	//driver::KeAllocateMemory(driver::ProcessId, &ShellCodeAddress, sizeof MemLoadShellcode_x64);

	//driver::KeAllocateMemory(driver::ProcessId, &CallShellCode, 0x1000);

	//BYTE callbytes[]{ 72,131,236,56,72,185,0,0,0,0,0,0,0,0,72,184,0,0,0,0,0,0,0,0,255,208,72,131,196,56 , 195 };
	//*(ULONG64*)(callbytes + 6) = (ULONG64)DllAddress;
	//*(ULONG64*)(callbytes + 16) = (ULONG64)ShellCodeAddress;

	//driver::WPM(DllAddress, filebuf, filelen);
	//driver::WPM(ShellCodeAddress, MemLoadShellcode_x64, sizeof MemLoadShellcode_x64);
	//driver::WPM(CallShellCode, callbytes, sizeof callbytes);
	//printf("CallShellCode %llX\n", CallShellCode);
	std::cin.get();

	driver::kernel_uesr_CreateThread(driver::ProcessId, PVOID(0x24872F00000), nullptr);
	Sleep(3000);



		//UCHAR buf[5]{};

		//auto start = timeGetTime();
		//for (size_t i = 0; i < 1000000; i++)
		//{
		//	driver::RPM(0x7FF652B23F40);
		//	//driver::KeReadProcesMemory(driver::ProcessId, 0x7FF652B23F40, buf, 5);
		//}
		//auto end = timeGetTime();


		//for (size_t i = 0; i < sizeof buf; i++)
		//{
		//	printf("%X ", buf[i]);
		//}

		//printf("\nUse Time: %d\n", ((end - start)));

		Sleep(100000);
	return 0;
}

