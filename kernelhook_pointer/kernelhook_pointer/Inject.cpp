#include "pch.h"
#include "Inject.h"


wchar_t* (*pwcsstr)(wchar_t*, wchar_t*) = nullptr;
NTSTATUS(*pCmRegisterCallbackEx)(PEX_CALLBACK_FUNCTION, PCUNICODE_STRING, PVOID, PVOID, PLARGE_INTEGER, PVOID) = nullptr;
NTSTATUS(*pCmUnRegisterCallback)(LARGE_INTEGER) = nullptr;
NTSTATUS(*pZwAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG) = nullptr;
NTSTATUS(*pZwFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG) = nullptr;
NTSTATUS(*pRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOL, ULONG, PULONG, PULONG, LPVOID, LPVOID, HANDLE, PCLIENT_ID) = nullptr;
NTSTATUS(*pZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG) = nullptr;
NTSTATUS(*pZwWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER) = nullptr;
NTSTATUS(*pZwClose)(HANDLE) = nullptr;
PVOID(*pExAllocatePoolWithTag)(POOL_TYPE, SIZE_T, ULONG) = nullptr;
void(*pExFreePoolWithTag)(PVOID, ULONG) = nullptr;

NTSTATUS Inject::InitializeFunction()
{
    UNICODE_STRING str{};
    RtlInitUnicodeString(&str, L"wcsstr");
    pwcsstr = reinterpret_cast<wchar_t* (*)(wchar_t*, wchar_t*)>(MmGetSystemRoutineAddress(&str));
    if (!pwcsstr)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"CmRegisterCallbackEx");
    pCmRegisterCallbackEx = reinterpret_cast<NTSTATUS(*)(PEX_CALLBACK_FUNCTION, PCUNICODE_STRING, PVOID, PVOID, PLARGE_INTEGER, PVOID)>(MmGetSystemRoutineAddress(&str));
    if (!pCmRegisterCallbackEx)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"CmUnRegisterCallback");
    pCmUnRegisterCallback = reinterpret_cast<NTSTATUS(*)(LARGE_INTEGER)>(MmGetSystemRoutineAddress(&str));
    if (!pCmUnRegisterCallback)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"ZwAllocateVirtualMemory");
    pZwAllocateVirtualMemory = reinterpret_cast<NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(MmGetSystemRoutineAddress(&str));
    if (!pZwAllocateVirtualMemory)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"ZwFreeVirtualMemory");
    pZwFreeVirtualMemory = reinterpret_cast<NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(MmGetSystemRoutineAddress(&str));
    if (!pZwFreeVirtualMemory)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"RtlCreateUserThread");
    pRtlCreateUserThread = reinterpret_cast<NTSTATUS(*)(HANDLE, PSECURITY_DESCRIPTOR, BOOL, ULONG, PULONG, PULONG, LPVOID, LPVOID, HANDLE, PCLIENT_ID)>(MmGetSystemRoutineAddress(&str));
    if (!pRtlCreateUserThread)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"ZwQueryInformationProcess");
    pZwQueryInformationProcess = reinterpret_cast<NTSTATUS(*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(MmGetSystemRoutineAddress(&str));
    if (!pZwQueryInformationProcess)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"ZwWaitForSingleObject");
    pZwWaitForSingleObject = reinterpret_cast<NTSTATUS(*)(HANDLE, BOOLEAN, PLARGE_INTEGER)>(MmGetSystemRoutineAddress(&str));
    if (!pZwWaitForSingleObject)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"ZwClose");
    pZwClose = reinterpret_cast<NTSTATUS(*)(HANDLE)>(MmGetSystemRoutineAddress(&str));
    if (!pZwClose)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"ExAllocatePoolWithTag");
    pExAllocatePoolWithTag = reinterpret_cast<PVOID(*)(POOL_TYPE, SIZE_T, ULONG)>(MmGetSystemRoutineAddress(&str));
    if (!pExAllocatePoolWithTag)
        return STATUS_INVALID_ADDRESS;
    RtlInitUnicodeString(&str, L"ExFreePoolWithTag");
    pExFreePoolWithTag = reinterpret_cast<void(*)(PVOID, ULONG)>(MmGetSystemRoutineAddress(&str));
    if (!pExFreePoolWithTag)
        return STATUS_INVALID_ADDRESS;
    return STATUS_SUCCESS;
}

void Inject::KeInjectDll(HANDLE ProcessId, PVOID DllBuffer, SIZE_T dwSize)
{
    NTSTATUS status{};
    PEPROCESS epGame{};
    KAPC_STATE Apc{};
    PVOID ShellPtr{}, DllPtr{}, CallPtr{};
    SIZE_T OldSize{ dwSize };
    PVOID TempDll{};
    TempDll = pExAllocatePoolWithTag(PagedPool, dwSize, 0);
    if (!TempDll)
        return;
    __stosb(PBYTE(TempDll), 0, dwSize);
    __movsb(PBYTE(TempDll), PBYTE(DllBuffer), dwSize);


    BYTE ShellCoder[]{
        0x48,0x83,0xEC,0x38,
        0x48,0xB9,0,0,0,0,0,0,0,0,
        0x48,0xB8,0,0,0,0,0,0,0,0,
        0xFF,0xD0,
        0x48,0x83,0xC4,0x38,
        0xC3
    };
    SIZE_T ShellSize{ sizeof(MemLoadShellcode_x64) }, CallSize{ PAGE_SIZE }, FreeSize{};
    HANDLE hThread{};
    status = PsLookupProcessByProcessId(ProcessId, &epGame);
    if (!NT_SUCCESS(status))
        goto Exit;
    KeStackAttachProcess(epGame, &Apc);
    status = pZwAllocateVirtualMemory(NtCurrentProcess(), &ShellPtr, 0, &ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
        goto Exit;
    status = pZwAllocateVirtualMemory(NtCurrentProcess(), &DllPtr, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
        goto Exit;
    status = pZwAllocateVirtualMemory(NtCurrentProcess(), &CallPtr, 0, &CallSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
        goto Exit;
    __movsb(PUCHAR(ShellPtr), MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64));

    __movsb(PUCHAR(DllPtr), PUCHAR(TempDll), OldSize);
    *(PULONG64)(ShellCoder + 6) = (ULONG64)DllPtr;
    *(PULONG64)(ShellCoder + 16) = (ULONG64)ShellPtr;
    __movsb(PUCHAR(CallPtr), ShellCoder, sizeof(ShellCoder));
    status = pRtlCreateUserThread(NtCurrentProcess(), nullptr, false, 0, nullptr, nullptr, CallPtr, DllPtr, &hThread, nullptr);

    if (!NT_SUCCESS(status))
        goto Exit;
    status = pZwWaitForSingleObject(hThread, false, nullptr);
    pZwClose(hThread);
Exit:
    if (ShellPtr)
    {
        pZwFreeVirtualMemory(NtCurrentProcess(), &ShellPtr, &FreeSize, MEM_RELEASE);
        ShellPtr = nullptr;
    }
    if (DllPtr)
    {
        pZwFreeVirtualMemory(NtCurrentProcess(), &DllPtr, &FreeSize, MEM_RELEASE);
        DllPtr = nullptr;
    }
    if (CallPtr)
    {
        pZwFreeVirtualMemory(NtCurrentProcess(), &CallPtr, &FreeSize, MEM_RELEASE);
        CallPtr = nullptr;
    }
    KeUnstackDetachProcess(&Apc);
    if (epGame)
        ObfDereferenceObject(epGame);
    if (TempDll)
    {
        pExFreePoolWithTag(TempDll, 0);
        TempDll = nullptr;
    }
}

bool Inject::InjectDll(PCommunication command)
{

    if (!command->DllBuffer)
        return false;
    if (!command->dwSize)
        return false;
    if (!command->ProcessId)
        return false;
    Inject::KeInjectDll(HANDLE(command->ProcessId), command->DllBuffer, command->dwSize);
    return true;
}

NTSTATUS Inject::UesrCreateHandle(PCommunication command)
{
    if (!command->ProcessId || !command->Address)
        return 0x1000;
    HANDLE hThread{};
    HANDLE hProcess{};
    OBJECT_ATTRIBUTES Object{};
    InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    CLIENT_ID Cid{};
    Cid.UniqueProcess = HANDLE(command->ProcessId);
    auto status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &Cid);
    if (!NT_SUCCESS(status))
        return status;
    status = pRtlCreateUserThread(hProcess, nullptr, false, 0, nullptr, nullptr, command->Address, command->Buffer, &hThread, nullptr);
    if (!NT_SUCCESS(status))
    {
        pZwClose(hProcess);
        return status;
    }
    status = pZwWaitForSingleObject(hThread, false, nullptr);
    if (!NT_SUCCESS(status))
    {
        pZwClose(hProcess);
        pZwClose(hThread);
        return status;
    }
    pZwClose(hThread);
    pZwClose(hProcess);
    return status;
}
