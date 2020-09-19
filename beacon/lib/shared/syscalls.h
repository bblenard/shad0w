#include <windows.h>

#define SYSCALL_STUB_SIZE 23
#define NTDLL_PATH "C:\\Windows\\System32\\ntdll.dll"

typedef NTSTATUS (NTAPI * _NtAllocateVirtualMemory) (
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef NTSTATUS (NTAPI * _NtProtectVirtualMemory) (
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG   NewAccessProtection,
    PULONG  OldAccessProtection
);

#ifndef STAGER
typedef NTSTATUS (NTAPI * _NtWriteVirtualMemory) (
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    PVOID  Buffer,
    ULONG  BufferSize,
    PULONG NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI * _NtQueueApcThread) (
    HANDLE          ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID           NormalContext,
    PVOID           SystemArgument1,
    PVOID           SystemArgument2
);

typedef NTSTATUS (NTAPI * _NtAlertResumeThread) (
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

typedef NTSTATUS (NTAPI * _NtOpenProcess) (
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID*         ClientId
);

typedef NTSTATUS (NTAPI * _NtOpenThread) (
    PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

typedef NTSTATUS (NTAPI * _NtSuspendThread)(
    HANDLE ThreadHandle
);

typedef NTSTATUS (NTAPI * _NtGetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT Context
);

typedef NTSTATUS (NTAPI * _NtSetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT Context
);

typedef NTSTATUS (NTAPI * _NtResumeThread)(
    HANDLE ThreadHandle
);
#endif


struct NtInfo
{
	PIMAGE_EXPORT_DIRECTORY pExprtDir;
	LPVOID					lpRawData;
	PIMAGE_SECTION_HEADER	pTextSection;
	PIMAGE_SECTION_HEADER	pRdataSection;
	CHAR	  				cSyscallStub;
};

struct Syscalls
{
	_NtAllocateVirtualMemory NtAllocateVirtualMemory;
    _NtProtectVirtualMemory  NtProtectVirtualMemory;
    #ifndef STAGER
    _NtWriteVirtualMemory    NtWriteVirtualMemory;
    _NtQueueApcThread        NtQueueApcThread;
    _NtOpenProcess           NtOpenProcess;
    _NtOpenThread            NtOpenThread;
    _NtSuspendThread         NtSuspendThread;
    _NtGetContextThread      NtGetContextThread;
    _NtSetContextThread      NtSetContextThread;
    _NtResumeThread          NtResumeThread;
    #endif
};

extern CHAR SyscallStub[SYSCALL_STUB_SIZE];