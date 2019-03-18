#include <ntddk.h>

#ifndef PBYTE
#define PBYTE PUCHAR
#endif
#ifndef UINT
#define UINT unsigned int
#endif
#define SHELLCODE_SIZE 4096
#define TAG ((ULONG)("USN"))

#define SIZE_JMPCODE 7

VOID CodeCopy(PVOID P);
VOID __stdcall DriverUnload(PVOID P,PDRIVER_OBJECT DriverObject);
//void __declspec(naked) ShellCode();