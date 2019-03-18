#include "DriverHello.h"

PCHAR StrHello = "\nHello World\n";

void __declspec(naked) ShellCode()
{
	__asm {
		nop;
		push eax;
		call _start;
		nop;
		nop;
		nop;
		nop;
	_start:
		mov eax, StrHello;
		push eax;
		lea eax, DbgPrint;
		call eax;
		add esp, 4;

		push ebp;
		mov ebp, esp;
		mov eax,DWORD PTR [ebp + 0Ch];
		mov DWORD PTR [ebp + 8], eax;
		mov eax, DWORD PTR [ebp+4];
		sub eax, SIZE_JMPCODE;
		mov DWORD PTR [ebp + 0Ch], eax;
		mov eax, [eax + SIZE_JMPCODE];
		pop ebp;
		add esp, 4;
		jmp eax;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;
		int 3;

	};
}


NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	//__asm int 3;
	DbgPrint("\n########################\nHello World\n");
	PVOID P = NULL, pMap = NULL;
	PMDL pMdl = NULL;
	NTSTATUS Status = STATUS_PENDING;
	__try {
		P = ExAllocatePoolWithTag(NonPagedPool, SHELLCODE_SIZE, TAG);
		if (P == NULL) {
			Status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}
		pMdl = IoAllocateMdl(P, SHELLCODE_SIZE, FALSE, FALSE, NULL);
		if (pMdl == NULL) {
			Status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}
		//CodeCopy(P);
		MmBuildMdlForNonPagedPool(pMdl);
		pMap = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, MdlMappingNoExecute);
		if (pMap == NULL) __leave;
		CodeCopy(pMap);
		if ((Status = MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READ)) != STATUS_SUCCESS) __leave;
#pragma warning(disable:4152)
		DriverObject->DriverUnload = P;

	}
	__finally {
		PCHAR C = NULL;
		switch (Status) {
		case STATUS_SUCCESS:
			C = "";
			break;
		case STATUS_NOT_MAPPED_VIEW:
			C = "\nHasn\'t Mapped\n";
			break;
		case STATUS_INVALID_PAGE_PROTECTION:
			C = "\nAccess Denied\n";
			break;
		default:
			C = "\nUnknown Status\n";
			break;
		}
		DbgPrint(C);

		if (pMap != NULL) {
			MmUnmapLockedPages(pMap, pMdl);
		}
		if (pMdl != NULL) {
			IoFreeMdl(pMdl);
		}
		if (Status != STATUS_SUCCESS) {
			if (P != NULL) {
				ExFreePoolWithTag(P, TAG);
			}
		}
	}


	//DriverObject->DriverExtension
	//MmProtectMdlSystemAddress

	return Status;
}

VOID CodeCopy(PVOID P) {
		UINT _CcCount = 0;
		UINT Index = 0;
#pragma warning(disable:4054)
		for (PBYTE f = (PBYTE)((PVOID)ShellCode), t = (PBYTE)P; Index < SHELLCODE_SIZE; f++, t++, Index++) {
			if (Index == SIZE_JMPCODE) {
				*(PULONG)t = (ULONG)((PVOID)DriverUnload);
				Index += 3;
				f += 3;
				t += 3;
				continue;
			}
			if ((*t = *f) == 0xcc) {
				if (++_CcCount >= 0x10)
					break;
			}
			else
				_CcCount = 0;
		}
}

VOID __stdcall DriverUnload(PVOID P,PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	//UNREFERENCED_PARAMETER(P);

	ExFreePoolWithTag(P, TAG);
	return;
}

