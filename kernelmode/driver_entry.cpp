#include "stdafx.h"

//no reason to create our own trash just use someone else driver)

// communicate with driver via readfile
NTSTATUS read_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(info);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

// communicate with driver via writefile
NTSTATUS write_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(info);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

// communticate with driver via ioctl
NTSTATUS ctl_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(info);

	auto stack = IoGetCurrentIrpStackLocation(irp);

	auto buffer = (p_info)irp->AssociatedIrp.SystemBuffer;

	if (stack) {
		if (buffer && sizeof(*buffer) >= sizeof(info)) {

			if (stack->Parameters.DeviceIoControl.IoControlCode == read) {
				read_mem(buffer->pid, (uintptr_t*)buffer->address, &buffer->value, buffer->size);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == write) {
				write_mem(buffer->pid, (uintptr_t*)buffer->address, &buffer->value, buffer->size);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == open) {
				buffer->data = (void*)open_handle(buffer->pid); // open kernel mode handle
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == base) {
				PEPROCESS pe;
				PsLookupProcessByProcessId((HANDLE)buffer->pid, &pe);
				buffer->data = PsGetProcessSectionBaseAddress(pe); //get process base address, also can be done with zwqueryinfo + can get base addresses of modules in process
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == hjack) {
				// add thread hjack function to inject into eac\be proctected games
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == hook) {
				// use smthing like shit antivirus(avast, etc)
			}
		}
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}


// real main
NTSTATUS driver_initialize(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {

	auto        status = STATUS_SUCCESS;
	UNICODE_STRING  sym_link, dev_name;
	PDEVICE_OBJECT  dev_obj;

	RtlInitUnicodeString(&dev_name, L"\\Device\\kernelmode");
	status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	RtlInitUnicodeString(&sym_link, L"\\DosDevices\\kernelmode");

	status = IoCreateSymbolicLink(&sym_link, &dev_name);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	dev_obj->Flags |= DO_BUFFERED_IO;

	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		driver_obj->MajorFunction[t] = unsupported_io;

	driver_obj->MajorFunction[IRP_MJ_READ] = read_io;
	driver_obj->MajorFunction[IRP_MJ_WRITE] = write_io;
	driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io;
	driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io;
	driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
	driver_obj->DriverUnload = NULL;// usupported due to unusual driver load
	
	dev_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}

// fake main
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
	auto        status = STATUS_SUCCESS;
	UNICODE_STRING  drv_name;

	RtlInitUnicodeString(&drv_name, L"\\Driver\\kernelmode");
	status = IoCreateDriver(&drv_name, &driver_initialize);

	clean_unloaded_drivers();//clean up
	return STATUS_SUCCESS;
}


NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp)
{
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}


NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp)
{
	UNREFERENCED_PARAMETER(device_obj);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}


//open handle from kernel mode
HANDLE open_handle(int pid)
{
	auto status = STATUS_SUCCESS;
	PEPROCESS pe;
	status = PsLookupProcessByProcessId((HANDLE)pid, &pe);

	if (status != STATUS_SUCCESS)
		return 0;

	HANDLE process_handle;

	status = ObOpenObjectByPointer(pe,
		0,
		NULL,
		PROCESS_ALL_ACCESS,
		*PsProcessType,
		KernelMode,
		&process_handle);

	if (status != STATUS_SUCCESS)
		return 0;

	return process_handle;
}

// clear our driver mapper
NTSTATUS clean_unloaded_drivers() {

	ULONG bytes = 0;
	auto status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return STATUS_UNSUCCESSFUL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, pooltag); // 'ENON'

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	uintptr_t ntoskrnlBase = 0, ntoskrnlSize = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (!strcmp((char*)module[i].FullPathName, "\\SystemRoot\\system32\\ntoskrnl.exe"))
		{
			ntoskrnlBase = (uintptr_t)module[i].ImageBase;
			ntoskrnlSize = (uintptr_t)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, pooltag);

	if (ntoskrnlBase <= 0)
		return STATUS_UNSUCCESSFUL;

	// NOTE: 4C 8B ? ? ? ? ? 4C 8B C9 4D 85 ? 74 + 3 + current signature address = MmUnloadedDrivers
	uintptr_t mmUnloadedDriversPtr = occurence((uintptr_t)ntoskrnlBase, (uintptr_t)ntoskrnlSize, "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

	if (!mmUnloadedDriversPtr)
		return STATUS_UNSUCCESSFUL;

	uintptr_t mmUnloadedDrivers = (uintptr_t)((PUCHAR)mmUnloadedDriversPtr + *(PULONG)((PUCHAR)mmUnloadedDriversPtr + 3) + 7);
	uintptr_t bufferPtr = *(uintptr_t*)mmUnloadedDrivers;

	// NOTE: 0x7D0 is size of the MmUnloadedDrivers array for win 7 and above
	PVOID newBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, 0x7D0, pooltag);

	if (!newBuffer)
		return STATUS_UNSUCCESSFUL;

	memset(newBuffer, 0, 0x7D0);

	// replace MmUnloadedDrivers
	*(uintptr_t*)mmUnloadedDrivers = (uintptr_t)newBuffer;

	// NOTE: clean the old buffer
	ExFreePoolWithTag((PVOID)bufferPtr, 0x54446D4D); // 'MmDT'
	ExFreePoolWithTag(newBuffer, pooltag);

	return STATUS_SUCCESS;
}

void write_mem(int pid, uintptr_t* addr, uintptr_t* value, uintptr_t size) {
	PEPROCESS pe;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &pe);

	MmCopyVirtualMemory(PsGetCurrentProcess(), value, pe, addr, size, KernelMode, &bytes);
}

void read_mem(int pid, uintptr_t* addr, uintptr_t* value, uintptr_t size) {
	PEPROCESS pe;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &pe);
	MmCopyVirtualMemory(pe, addr, PsGetCurrentProcess(), value, size, KernelMode, &bytes);
}

char compare(const char* data, const char* pattern, const char* mask) {
	for (; *mask; ++mask, ++data, ++pattern)
		if (*mask == 'x' && *data != *pattern)
			return 0;

	return (*mask) == 0;
}

// pattern scan in kernel space
uintptr_t occurence(uintptr_t address, size_t lenth, char *pattern, char * mask) {
	for (uintptr_t i = 0; i < lenth; i++)
		if (compare((const char*)(address + i), pattern, mask))
			return (uintptr_t)(address + i);

	return 0;
}
