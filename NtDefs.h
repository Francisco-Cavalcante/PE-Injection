// compare to https://github.com/MalwareTech/ZombifyProcess/ thanks  : )
typedef struct
{
	WORD	Offset : 12;
	WORD	Type : 4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;
DWORD Inject(LPTHREAD_START_ROUTINE Function, HANDLE proc);
VOID ProcessRelocations(PIMAGE_BASE_RELOCATION Relocs, DWORD ImageBase, DWORD Delta, DWORD Size);

void GetImageBase();

typedef struct _ZombiePool
{
	LPVOID Remote;
	LPVOID Local;
}ZombiePool, *PZombiePool;


#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI* NtCreateSection_)(_Out_     PHANDLE SectionHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_  PLARGE_INTEGER MaximumSize,
	_In_      ULONG SectionPageProtection,
	_In_      ULONG AllocationAttributes,
	_In_opt_  HANDLE FileHandle
	);

typedef NTSTATUS(WINAPI* NtMapViewOfSection_)(
	_In_         HANDLE SectionHandle,
	_In_         HANDLE ProcessHandle,
	_Inout_      PVOID *BaseAddress,
	_In_         ULONG_PTR ZeroBits,
	_In_         SIZE_T CommitSize,
	_Inout_opt_  PLARGE_INTEGER SectionOffset,
	_Inout_      PSIZE_T ViewSize,
	_In_         DWORD InheritDisposition,
	_In_         ULONG AllocationType,
	_In_         ULONG Win32Protect
	);


typedef NTSTATUS(WINAPI* NtUnmapViewOfSection_)(_In_      HANDLE ProcessHandle,
	_In_opt_  PVOID BaseAddress);


typedef NTSTATUS(WINAPI* NtClose_)(HANDLE Handle);



void * GetProcAddress32(void * lvpBaseAddress, char * lpszProcName);
void* GetModuleBase32(wchar_t* szModule);

DWORD GetModuleSize(HMODULE hModule);


typedef struct _PEB_LDR_DATA {
	DWORD dwLength;
	DWORD Initialized;
	DWORD ssHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
}PEB32, *PPEB32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
