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
	uintptr_t address;
	uintptr_t value;
	uintptr_t size;
	void* data;
}info, *p_info;


#define write    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdead, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define read    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdaed, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define open    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdeed, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define base    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdedd, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define hook    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xeedd, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define hjack    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xdeaf, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define pooltag 'dEad'

//io
NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp);
NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp);
NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp);

// memory
void write_mem(int pid, uintptr_t* addr, uintptr_t* value, uintptr_t size);
void read_mem(int pid, uintptr_t* addr, uintptr_t* value, uintptr_t size);
uintptr_t occurence(uintptr_t address, size_t lenth, char *pattern, char * mask);
HANDLE open_handle(int pid);
NTSTATUS clean_unloaded_drivers();

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	NTKERNELAPI NTSTATUS ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID * Object);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,PSIZE_T ReturnSize);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
}