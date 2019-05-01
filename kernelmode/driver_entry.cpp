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

			if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_read) {
				read_mem(buffer->pid, buffer->address, buffer->value, buffer->size);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_write) {
				write_mem(buffer->pid, buffer->address, buffer->value, buffer->size); //writes value to 
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_open) {
				buffer->data = (void*)open_handle(buffer->pid); // open kernel mode handle
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_base) {
				PEPROCESS pe;
				PsLookupProcessByProcessId((HANDLE)buffer->pid, &pe);
				buffer->data = PsGetProcessSectionBaseAddress(pe); //get process base address, also can be done with zwqueryinfo + can get base addresses of modules in process
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_alloc) {
				alloc_mem(buffer); // allocate memory in target process
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_free) {
				free_mem(buffer); // free memory in target process
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
		DbgPrint("Failed create device");
		return status;
	}

	RtlInitUnicodeString(&sym_link, L"\\DosDevices\\kernelmode");

	status = IoCreateSymbolicLink(&sym_link, &dev_name);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Failed create symbolic link");
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

	clean_unloaded_drivers();// clean up
	clean_piddb_cache();// clean up
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

// clear our driver mapper
void clean_piddb_cache() {
	//863E00 - PiDDBCacheTable \x48\x8D\x0D\x00\x00\x00\x00\x4C\x89\x35\x00\x00\x00\x00\x49\x8B\xE9, xxx????xxx????xxx
	//3C8240 - PiDDBLock \x48\x8D\x0D\x00\x00\x00\x00\x48\x89\x00, xxx????xxx
	//gay way

	PERESOURCE PiDDBLock; PRTL_AVL_TABLE PiDDBCacheTable;

	//PiDDBCacheTable = PRTL_AVL_TABLE(ntoskrnlBase + 0x863E00);
	//PiDDBLock = PERESOURCE(ntoskrnlBase + 0x3C8240);

	size_t size;
	uintptr_t ntoskrnlBase = get_kerneladdr("ntoskrnl.exe", size);

	PiDDBCacheTable = (PRTL_AVL_TABLE)dereference(find_pattern<uintptr_t>((void*)ntoskrnlBase, size, "\x48\x8D\x0D\x00\x00\x00\x00\x4C\x89\x35\x00\x00\x00\x00\x49\x8B\xE9", "xxx????xxx????xxx"), 3);
	PiDDBLock = (PERESOURCE)dereference(find_pattern<uintptr_t>((void*)ntoskrnlBase, size, "\x48\x8D\x0D\x00\x00\x00\x00\x48\x89\x00", "xxx????xxx"), 3);

	DbgPrint("PiDDBCacheTable: %d", PiDDBCacheTable);
	DbgPrint("PiDDBLock: %d", PiDDBLock);

	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

	//just for fun, there were more properly method for doing it, or you can call RtlCompareUnicodeString and rename only needed driver
	UNICODE_STRING dest_str;
	RtlInitUnicodeString(&dest_str, L"weavetophvh.sys");

	uintptr_t entry_address = uintptr_t(PiDDBCacheTable->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);
	piddbcache* entry = (piddbcache*)(entry_address);

	DbgPrint("First piddbcache entry: %wZ", entry->DriverName);

	entry->DriverName = dest_str;
	entry->TimeDateStamp = 0x863E1;

	ULONG count = 0;

	for (auto link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++)
	{
		piddbcache* cache_entry = (piddbcache*)(link);

		DbgPrint("cache_entry count: %lu name: %wZ \t\t stamp: %x",
			count,
			cache_entry->DriverName,
			cache_entry->TimeDateStamp);

		cache_entry->DriverName = dest_str;
		cache_entry->TimeDateStamp = 0x863E00 + count;
	}

	// release the ddb resource lock
	ExReleaseResourceLite(PiDDBLock);
}


// open handle from kernel mode
HANDLE open_handle(int pid)
{
	auto status = STATUS_SUCCESS;
	PEPROCESS pe;
	PsLookupProcessByProcessId((HANDLE)pid, &pe);

	HANDLE process_handle;

	status = ObOpenObjectByPointer(pe,
		0,
		NULL,
		PROCESS_ALL_ACCESS,
		*PsProcessType,
		KernelMode,
		&process_handle);

	if (status != STATUS_SUCCESS) {
		DbgPrint("ObOpenObjectByPointer failed(handle)");
		return 0;
	}

	return process_handle;
}

uintptr_t get_kerneladdr(const char* name, size_t& size)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
	);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, pooltag);
	if (!pModuleList) {
		DbgPrint("ExAllocatePoolWithTag failed(kernel addr)");
		return 0;
	}
	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);

	ULONG i = 0;
	uintptr_t address = 0;

	for (i = 0; i < pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = uintptr_t(pModuleList->Modules[i].Base);
		size = uintptr_t(pModuleList->Modules[i].Size);
		if (strstr(mod.ImageName, name) != NULL)
			break;
	}

	ExFreePoolWithTag(pModuleList, pooltag);

	return address;
}


// clear our driver mapper
void clean_unloaded_drivers() {

	ULONG bytes = 0;
	auto status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, pooltag); // 'ENON'

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwQuerySystemInformation failed(unloaded drivers)");
		ExFreePoolWithTag(modules, pooltag);
		return;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	uintptr_t ntoskrnlBase = 0;
	size_t ntoskrnlSize = 0;

	ntoskrnlBase = get_kerneladdr("ntoskrnl.exe", ntoskrnlSize);

	ExFreePoolWithTag(modules, pooltag);

	if (ntoskrnlBase <= 0) {
		DbgPrint("get_kerneladdr failed(unloaded drivers)");
		return;
	}

	// NOTE: 4C 8B ? ? ? ? ? 4C 8B C9 4D 85 ? 74 + 3 + current signature address = MmUnloadedDrivers
	auto mmUnloadedDriversPtr = find_pattern<uintptr_t>((void*)ntoskrnlBase, ntoskrnlSize, "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

	DbgPrint("mmUnloadedDriversPtr: %d", mmUnloadedDriversPtr);

	if (!mmUnloadedDriversPtr) {
		DbgPrint("mmUnloadedDriversPtr equals 0(unloaded drivers)");
		return;
	}

	uintptr_t mmUnloadedDrivers = dereference(mmUnloadedDriversPtr, 3);

	memset(*(uintptr_t**)mmUnloadedDrivers, 0, 0x7D0);
}

void write_mem(int pid, void* addr, void* value, size_t size) {
	PEPROCESS pe;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &pe);

	MmCopyVirtualMemory(PsGetCurrentProcess(), value, pe, addr, size, KernelMode, &bytes);
}

void read_mem(int pid, void* addr, void* value, size_t size) {
	PEPROCESS pe;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &pe);
	MmCopyVirtualMemory(pe, addr, PsGetCurrentProcess(), value, size, KernelMode, &bytes);
}

void alloc_mem(p_info buff) {
	PEPROCESS pe;
	KAPC_STATE apc;
	auto type = (ULONG)buff->data;
	PsLookupProcessByProcessId((HANDLE)buff->pid, &pe);
	KeStackAttachProcess(pe, &apc);
	ZwAllocateVirtualMemory(ZwCurrentProcess(), &buff->address, 0, &buff->size, type, PAGE_EXECUTE_READWRITE);
	KeUnstackDetachProcess(&apc);
}

void free_mem(p_info buff) {
	PEPROCESS pe;
	KAPC_STATE apc;
	PsLookupProcessByProcessId((HANDLE)buff->pid, &pe);
	KeStackAttachProcess(pe, &apc);
	ZwFreeVirtualMemory(ZwCurrentProcess(), &buff->address, &buff->size, MEM_RELEASE);
	KeUnstackDetachProcess(&apc);
}


template <typename t = void*> //free pasta
t find_pattern(void* start, size_t length, const char* pattern, const char* mask)
{
	const auto data = static_cast<const char*>(start);
	const auto pattern_length = strlen(mask);

	for (size_t i = 0; i <= length - pattern_length; i++)
	{
		bool accumulative_found = true;

		for (size_t j = 0; j < pattern_length; j++)
		{
			if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + i + j)))
			{
				accumulative_found = false;
				break;
			}

			if (data[i + j] != pattern[j] && mask[j] != '?')
			{
				accumulative_found = false;
				break;
			}
		}

		if (accumulative_found)
		{
			return (t)(reinterpret_cast<uintptr_t>(data) + i);
		}
	}

	return (t)nullptr;
}

uintptr_t dereference(uintptr_t address, unsigned int offset)
{
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}
