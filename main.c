//===============================================================================================//
// Copyright (c) 2017, Mojtaba Zaheri of APA Research Center, Amirkabir University of Technology
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of APA Research Center nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#pragma once
#include "structs.h"
#include "utils.h"
#include "wdm.h"
#include "minifilt.h"
#include <ntifs.h>
#include <stdio.h>

#define DEVICE_NAME L"\\Device\\KMDFInjectionDriver"
#define LINK_NAME L"\\DosDevices\\KMDFInjectionDriverDriver"

PFLT_FILTER flt_handle;

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void UnloadDriver(PDRIVER_OBJECT DriverObject);

#define SIOCTL_TYPE 40000
#define IOCTL_HELLO\
 CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)


const WCHAR deviceNameBuffer[] = L"\\Device\\MYDEVICE";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\MyDevice";
PDEVICE_OBJECT g_MyDevice; // Global pointer to our device object


#define MY_TAG 'Tag1'

extern UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);;


NTSTATUS Function_IRP_MJ_CREATE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("IRP MJ CREATE received.\n");
	return STATUS_SUCCESS;
}


NTSTATUS Function_IRP_MJ_CLOSE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("IRP MJ CLOSE received.\n");
	return STATUS_SUCCESS;
}


NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	PIO_STACK_LOCATION pIoStackLocation;
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	PCHAR welcome = "from kernel to user";

	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HELLO:
		DbgPrint("IOCTL HELLO.");
		DbgPrint("Message received : %s", pBuf);
		welcome = (PCHAR)pBuf;
		RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(pBuf, welcome, strlen(welcome));

		break;
	}

	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(welcome);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}



LPSTR GetProcessNameFromPid(HANDLE pid) {

	PEPROCESS Process;

	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER) {
		return "[ SelfProtect ] [ ERROR ]  PID required.";
	}

	return (LPSTR)PsGetProcessImageFileName(Process);
}

VOID ProcessCallback(IN HANDLE parentid, IN HANDLE pid, IN BOOLEAN create)

{
	UNREFERENCED_PARAMETER(parentid);

	LARGE_INTEGER CurrentGMTTime;
	LARGE_INTEGER CurrentLocalTime;
	TIME_FIELDS CurrentLocalTimeField;

	UNICODE_STRING			LogFileName;
	OBJECT_ATTRIBUTES		ObjAttr;
	NTSTATUS				Status = STATUS_SUCCESS;
	HANDLE					hLogFile;
	IO_STATUS_BLOCK			IOStatus;
	PCHAR					LogEntryText;
	ULONG					LogEntryTextLen;
	LARGE_INTEGER			liFileOffset;

	KeQuerySystemTime(&CurrentGMTTime);
	ExSystemTimeToLocalTime(&CurrentGMTTime, &CurrentLocalTime);
	RtlTimeToTimeFields(&CurrentLocalTime, &CurrentLocalTimeField);


	RtlInitUnicodeString(&LogFileName, L"\\??\\C:\\ProcLogger.log");
	InitializeObjectAttributes(
		&ObjAttr,
		&LogFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL, NULL);

	if (!NT_SUCCESS(Status = ZwCreateFile(
		&hLogFile,
		GENERIC_WRITE,
		&ObjAttr,
		&IOStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL, 0)))
	{
		DbgPrint("[ ProcLogger ] [ Log ] [ Error ] zwWriteFile Error (0x%p)\n", (void*)Status);
		return;
	}

	LogEntryText = ExAllocatePoolWithTag(PagedPool, 1024, MY_TAG);



	switch (create)

	{

	case TRUE:

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[0x%X] process is creating\n", pid);
		sprintf(LogEntryText, "[ %d:%d:%d:%d:%d:%d ] [0x%Ix] %s is creating\n", CurrentLocalTimeField.Year,
			CurrentLocalTimeField.Month,
			CurrentLocalTimeField.Day,
			CurrentLocalTimeField.Hour,
			CurrentLocalTimeField.Minute,
			CurrentLocalTimeField.Second, (ULONG_PTR)pid, GetProcessNameFromPid(pid));

		break;

	case FALSE:

		DbgPrint("[0x%X] process is deleting\n", pid);
		sprintf(LogEntryText, "[ %d:%d:%d:%d:%d:%d ] [0x%Ix] %s process is deleting\n", 
			CurrentLocalTimeField.Year,
			CurrentLocalTimeField.Month,
			CurrentLocalTimeField.Day,
			CurrentLocalTimeField.Hour,
			CurrentLocalTimeField.Minute,
			CurrentLocalTimeField.Second, (ULONG_PTR)pid, GetProcessNameFromPid(pid));

		break;

	}

	LogEntryTextLen = strlen(LogEntryText);

	liFileOffset.HighPart = -1;
	liFileOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;

	Status = ZwWriteFile(
		hLogFile,
		NULL, NULL, NULL,
		&IOStatus,
		LogEntryText,
		LogEntryTextLen,
		&liFileOffset,
		NULL);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("[ ProcLogger ] [ Log ] [ Error ] zwWriteFile Fail (0x%x)", Status);
		ZwClose(hLogFile);
	}

	ExFreePoolWithTag(LogEntryText, MY_TAG);

	ZwClose(hLogFile);
}


VOID SysCallBack(IN PUNICODE_STRING imagePath, IN HANDLE pid, IN PIMAGE_INFO imageInfo)

{

	LARGE_INTEGER CurrentGMTTime;
	LARGE_INTEGER CurrentLocalTime;
	TIME_FIELDS CurrentLocalTimeField;

	UNICODE_STRING			LogFileName;
	OBJECT_ATTRIBUTES		ObjAttr;
	NTSTATUS				Status = STATUS_SUCCESS;
	HANDLE					hLogFile;
	IO_STATUS_BLOCK			IOStatus;
	PCHAR					LogEntryText;
	ULONG					LogEntryTextLen;
	LARGE_INTEGER			liFileOffset;

	KeQuerySystemTime(&CurrentGMTTime);
	ExSystemTimeToLocalTime(&CurrentGMTTime, &CurrentLocalTime);
	RtlTimeToTimeFields(&CurrentLocalTime, &CurrentLocalTimeField);


	RtlInitUnicodeString(&LogFileName, L"\\??\\C:\\DllLogger.log");
	InitializeObjectAttributes(
		&ObjAttr,
		&LogFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL, NULL);

	if (!NT_SUCCESS(Status = ZwCreateFile(
		&hLogFile,
		GENERIC_WRITE,
		&ObjAttr,
		&IOStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL, 0)))
	{
		DbgPrint("[ ProcLogger ] [ Log ] [ Error ] zwWriteFile Error (0x%p)\n", (void*)Status);
		return;
	}

	LogEntryText = ExAllocatePoolWithTag(PagedPool, 1024, MY_TAG);




	WCHAR* pwsName = NULL;



	if (imagePath == NULL)

		return;



	pwsName = (WCHAR*)ExAllocatePool(NonPagedPool, imagePath->Length + sizeof(WCHAR));



	memcpy(pwsName, imagePath->Buffer, imagePath->Length);

	pwsName[imagePath->Length / sizeof(WCHAR)] = 0;



	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[0x%X] (%ws) is loading\n", pid, pwsName);
	sprintf(LogEntryText, "[ %d:%d:%d:%d:%d:%d ] [0x%X] (%ws) is loading\n",
		CurrentLocalTimeField.Year,
		CurrentLocalTimeField.Month,
		CurrentLocalTimeField.Day,
		CurrentLocalTimeField.Hour,
		CurrentLocalTimeField.Minute,
		CurrentLocalTimeField.Second, pid, pwsName);


	if (imageInfo->SystemModeImage == 0)

		DbgPrint("type:[Driver]\n");



	else

		DbgPrint("type:[DLL]\n");





	if (pwsName)

		ExFreePool(pwsName);



	LogEntryTextLen = strlen(LogEntryText);

	liFileOffset.HighPart = -1;
	liFileOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;

	Status = ZwWriteFile(
		hLogFile,
		NULL, NULL, NULL,
		&IOStatus,
		LogEntryText,
		LogEntryTextLen,
		&liFileOffset,
		NULL);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("[ ProcLogger ] [ Log ] [ Error ] zwWriteFile Fail (0x%x)", Status);
		ZwClose(hLogFile);
	}

	ExFreePoolWithTag(LogEntryText, MY_TAG);

	ZwClose(hLogFile);

}


VOID OnImageLoadCallback(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO ImageInfo)
{

	// check If ntdll is loading
	if (InProcessId != 0 && InFullImageName != NULL && InFullImageName->Length > 0 && wcsstr(InFullImageName->Buffer, L"ntdll.dll"))
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS pProcess = NULL;
		status = PsLookupProcessByProcessId(InProcessId, &pProcess);
		BOOLEAN isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;


		// check if 64 bit ntdll is loading in 32 bit process
		if (isWow64 && wcsstr(InFullImageName->Buffer, L"System32"))
			return;

		// check if target process is protected
		if (PsIsProtectedProcess(pProcess))
			return;

		if (NT_SUCCESS(status))
		{
			KAPC_STATE apc;
			UNICODE_STRING ustrPath;
			PVOID pNtdll = NULL;
			PVOID LdrLoadDllLocal = NULL;

			KeStackAttachProcess(pProcess, &apc);

			// Get Ntdll address
			pNtdll = ImageInfo->ImageBase;

			// Get LdrLoadDll addresss
			LdrLoadDllLocal = SWIDGetModuleExport(pNtdll, "LdrLoadDll", pProcess, NULL);

			if (!LdrLoadDllLocal)
			{
				DPRINT("System Wide Injection Driver: %s: Failed to get LdrLoadDll address.\n", __FUNCTION__);
				status = STATUS_NOT_FOUND;
				KeUnstackDetachProcess(&apc);
				return;
			}

			// Call LdrLoadDll
			if (NT_SUCCESS(status))
			{
				PINJECT_BUFFER pUserBuf;
				if (isWow64)
				{
					RtlInitUnicodeString(&ustrPath, L"InjectionMitigationDLLx86.dll");
					pUserBuf = SWIDGetWow64Code(LdrLoadDllLocal, &ustrPath);
				}
				else
				{
					RtlInitUnicodeString(&ustrPath, L"InjectionMitigationDLLx64.dll");
					pUserBuf = SWIDGetNativeCode(LdrLoadDllLocal, &ustrPath);
				}

				status = SWIDApcInject(pUserBuf, (HANDLE)InProcessId);
			}

			KeUnstackDetachProcess(&apc);
		}
		else
		{
			DPRINT("System Wide Injection Driver: %s: PsLookupProcessByProcessId failed with status 0x%X.\n", __FUNCTION__, status);

			if (pProcess)
				ObDereferenceObject(pProcess);

			return;
		}

		if (pProcess)
			ObDereferenceObject(pProcess);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);


	NTSTATUS ntStatus = 0;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, deviceSymLinkBuffer);

	// Create the device.
	ntStatus = IoCreateDevice(DriverObject,
		0, // For driver extension
		&deviceNameUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_UNKNOWN,
		FALSE,
		&g_MyDevice);

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);



	PsSetCreateProcessNotifyRoutine(ProcessCallback, FALSE);
	PsSetLoadImageNotifyRoutine(SysCallBack);

	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;

	DbgPrint("Loading driver\n");

	return  STATUS_SUCCESS;
}


NTSTATUS DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING uniLinkName;
	PDEVICE_OBJECT CurrentDeviceObject;
	PDEVICE_OBJECT NextDeviceObject;
	UNICODE_STRING symLink;

	RtlInitUnicodeString(&symLink, deviceSymLinkBuffer);

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);


	PsSetCreateProcessNotifyRoutine(ProcessCallback, TRUE);
	PsRemoveLoadImageNotifyRoutine(SysCallBack);

	DPRINT("System Wide Injection Driver: %s: UnloadDriver.\n", __FUNCTION__);
}