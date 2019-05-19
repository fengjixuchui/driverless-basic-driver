#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntdddisk.h>
#include <scsi.h>
#include <intrin.h>

#include "structs.h"

typedef unsigned __int64 uintptr_t;

typedef struct info_t {
	int pid = 0;
	void* address;
	void* value;
	SIZE_T size;
	void* data;
}info, *p_info;


#define ctl_write    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdead, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_read    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdaed, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_open    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdeed, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_base    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdedd, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_alloc    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdddd, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_free    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xd, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


#define pooltag 'dEad'

//io
NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp);
NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp);
NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp);

// memory
void write_mem(int pid, void* addr, void* value, size_t size);
void read_mem(int pid, void* addr, void* value, size_t size);
void alloc_mem(p_info buff);
void free_mem(p_info buff);
uintptr_t get_kerneladdr(const char* name, size_t& size);
uintptr_t dereference(uintptr_t address, unsigned int offset);
template <typename t = void*>
t find_pattern(void* start, size_t length, const char* pattern, const char* mask);
HANDLE open_handle(int pid);
void clean_unloaded_drivers();
void clean_piddb_cache();


extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	NTKERNELAPI NTSTATUS ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID * Object);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
}
