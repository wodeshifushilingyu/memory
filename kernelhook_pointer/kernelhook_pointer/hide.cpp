#include "pch.h"
#include "hide.h"



extern "C" extern  POBJECT_TYPE * IoDriverObjectType;


typedef NTSTATUS(__fastcall* pfnMiProcessLoaderEntry)(PVOID pDriverSection, LOGICAL IsLoad);


typedef struct __LDR_DATA_TABLE_ENTRY1
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
}_LDR_DATA_TABLE_ENTRY1, * _PLDR_DATA_TABLE_ENTRY1;



NTSTATUS hide::GetDriverObjectByName(PDRIVER_OBJECT* DriverObject, WCHAR* DriverName)
{
    //VMPEX
    PDRIVER_OBJECT TempObject = NULL;
    UNICODE_STRING uDriverName = { 0 };
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    RtlInitUnicodeString(&uDriverName, DriverName);
    status = ObReferenceObjectByName(&uDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&TempObject);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("ObReferenceObjectByName failed\n"));
        *DriverObject = NULL;
        return status;
    }
    *DriverObject = TempObject;
    return status;
    //END
}

BOOLEAN hide::SupportSEH(PDRIVER_OBJECT DriverObject)
{
    //VMPEX
    //��Ϊ������������ժ��֮��Ͳ���֧��SEH��
    //������SEH�ַ��Ǹ��ݴ������ϻ�ȡ������ַ���ж��쳣�ĵ�ַ�Ƿ��ڸ�������
    //��Ϊ������û�ˣ��ͻ������
    //ѧϰ����Ϯ�����ķ������ñ��˵�����������������ϵĵ�ַ

    PDRIVER_OBJECT BeepDriverObject = NULL;;
    _PLDR_DATA_TABLE_ENTRY1 LdrEntry = NULL;

    GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\beep");
    if (BeepDriverObject == NULL)
        return FALSE;

    //MiProcessLoaderEntry��������ڲ������Ldr�е�DllBaseȻ��ȥRtlxRemoveInvertedFunctionTable�����ҵ���Ӧ����
    //֮�����Ƴ��������ݲ�������..�������û�е�DllBase��û������SEH������ԭ��û��...
    //����������ϵͳ��Driver\\beep��������...
    LdrEntry = (_PLDR_DATA_TABLE_ENTRY1)DriverObject->DriverSection;
    LdrEntry->DllBase = BeepDriverObject->DriverStart;
    ObDereferenceObject(BeepDriverObject);
    return TRUE;
    //END
}

//Win10-11 Only
PVOID hide::GetMiProcessLoaderEntry()
{
    //VMPEX
    UNICODE_STRING FuncName = { 0 };
    PUCHAR pfnMmUnloadSystemImage = NULL;
    PUCHAR pfnMiUnloadSystemImage = NULL;
    PUCHAR pfnMiProcessLoaderEntry = NULL;

    RtlInitUnicodeString(&FuncName, L"MmUnloadSystemImage");
    pfnMmUnloadSystemImage = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);

    if (pfnMmUnloadSystemImage && MmIsAddressValid(pfnMmUnloadSystemImage) && MmIsAddressValid((PVOID)((ULONG64)pfnMmUnloadSystemImage + 0xFF)))
    {
        /*
        PAGE:00000001403B1D80 48 8B D8                          mov     rbx, rax
        PAGE:00000001403B1D83 E8 D0 10 03 00                    call    MiUnloadSystemImage
        PAGE:00000001403B1D88 48 8B CB                          mov     rcx, rbx
        */
        for (PUCHAR start = pfnMmUnloadSystemImage; start < pfnMmUnloadSystemImage + 0xFF; ++start)
        {
            if (*(PULONG)start == 0xE8D88B48 && *(PUINT16)(start + 8) == 0x8B48 && start[0xA] == 0xCB)
            {
                start += 3;
                pfnMiUnloadSystemImage = start + *(PLONG)(start + 1) + 5;
                KdPrint(("pfnMiUnloadSystemImage = %p\n", pfnMiUnloadSystemImage));
            }
        }
    }
    KdPrint(("enter\n"));

    if (pfnMiUnloadSystemImage && MmIsAddressValid(pfnMiUnloadSystemImage) && MmIsAddressValid((PVOID)((ULONG64)pfnMiUnloadSystemImage + 0x600)))
    {
        //MiUnloadSystemImage
        //System        Length
        //15063         0X4FA
        //19043         0x69B
        //22000         0x7EF

        /*
                15063   19043   22000
        PAGE:00000001406EFE20                   loc_1406EFE20:                          ; CODE XREF: MiUnloadSystemImage+481��j
        PAGE:00000001406EFE20                                                           ; MiUnloadSystemImage+49A��j
        PAGE:00000001406EFE20 48 83 3B 00                       cmp     qword ptr [rbx], 0
        PAGE:00000001406EFE24 74 54                             jz      short loc_1406EFE7A
        PAGE:00000001406EFE26 33 D2                             xor     edx, edx
        PAGE:00000001406EFE28 48 8B CB                          mov     rcx, rbx
        PAGE:00000001406EFE2B E8 A4 F1 C7 FF                    call    MiProcessLoaderEntry
        PAGE:00000001406EFE30 8B 05 4A C6 60 00                 mov     eax, dword ptr cs:PerfGlobalGroupMask
        PAGE:00000001406EFE36 A8 04                             test    al, 4
        */

        for (PUCHAR start = pfnMiUnloadSystemImage; start < pfnMiUnloadSystemImage + 0x600; ++start)
        {
            if (*(PUINT16)start == 0xD233 && *(PULONG)(start + 2) == 0xE8CB8B48 && *(PUINT16)(start + 0xA) == 0x058B && *(PUINT16)(start + 0x10) == 0x04A8)
            {
                start += 5;
                pfnMiProcessLoaderEntry = start + *(PLONG)(start + 1) + 5;
                KdPrint(("pfnMiProcessLoaderEntry = %p\n", pfnMiProcessLoaderEntry));
                return pfnMiProcessLoaderEntry;
            }
        }
    }
    return NULL;
    //END
}


void hide::DriverReinitialize(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count)
{
    //VMPEX
    UNREFERENCED_PARAMETER(Count);
    UNREFERENCED_PARAMETER(Context);
    pfnMiProcessLoaderEntry MiProcessLoaderEntry = NULL;
    _PLDR_DATA_TABLE_ENTRY1 LdrEntry = { 0 };
    LdrEntry = (_PLDR_DATA_TABLE_ENTRY1)DriverObject->DriverSection;

    MiProcessLoaderEntry = (pfnMiProcessLoaderEntry)GetMiProcessLoaderEntry();
    if (!MiProcessLoaderEntry)
    {
        KdPrint(("GetMiProcessLoaderEntry failed\n"));
        return;
    }
    MiProcessLoaderEntry(DriverObject->DriverSection, 0);   //MiProcessLoaderEntry�������ж��Win10������Win7������

    SupportSEH(DriverObject);
    //END
    /*
    * ����+Ĩ��DriverObject�����ɹ�PCHunter
    * Win10 19043 ����BugCheck(0x109) PatchGuard
    * 19: Loaded module list modification
    */

    /*
    *((ULONGLONG*)LdrEntry->InLoadOrderLinks.Blink) = LdrEntry->InLoadOrderLinks.Flink;
    ((LIST_ENTRY64*)LdrEntry->InLoadOrderLinks.Flink)->Blink = LdrEntry->InLoadOrderLinks.Blink;

    InitializeListHead(&LdrEntry->InLoadOrderLinks);
    InitializeListHead(&LdrEntry->InMemoryOrderLinks);

    DriverObject->DriverSection = NULL;
    DriverObject->DriverStart = NULL;
    DriverObject->DriverSize = 0;
    DriverObject->DriverUnload = NULL;
    DriverObject->DriverInit = NULL;
    DriverObject->DeviceObject = NULL;
    */
}

NTSTATUS hide::HideDriver(PDRIVER_OBJECT DriverObject)
{
    //VMP
    NTSTATUS status = STATUS_SUCCESS;
    if (!MmIsAddressValid(DriverObject))
        return STATUS_INVALID_PARAMETER;
    IoRegisterDriverReinitialization(DriverObject, DriverReinitialize, NULL);
    DbgPrintEx(0, 0, "HideDriver  %p\n", DriverObject->DriverStart);
    return status;
    //END
}
