
#include <fltKernel.h>
#include "minifilt.h"
#include <windef.h>
#include <stdbool.h>
#include "wdm.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

FLT_OPERATION_REGISTRATION operations[] = {
	{
		IRP_MJ_CREATE,
		0,
		MinifltExampleCreatePreRoutine,
		MinifltExampleCreatePostRoutine,
		NULL
	},
	{
		IRP_MJ_OPERATION_END
	}
};





FLT_PREOP_CALLBACK_STATUS
MinifltExampleCreatePreRoutine
(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects); // 추가된 코드
	// 파일명 가져오기
	if (Data->Iopb->TargetFileObject && Data->Iopb->TargetFileObject->FileName.Length > 0) {
		UNICODE_STRING fileName = Data->Iopb->TargetFileObject->FileName;
		DbgPrint("File Opened: %wZ\n", &fileName);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS
MinifltExampleCreatePostRoutine(
	_Inout_      PFLT_CALLBACK_DATA data,
	_In_         PCFLT_RELATED_OBJECTS flt_object,
	_In_opt_     PVOID completion_context,
	_In_         FLT_POST_OPERATION_FLAGS flags
)
{
	UNREFERENCED_PARAMETER(flt_object);
	UNREFERENCED_PARAMETER(completion_context);
	UNREFERENCED_PARAMETER(flags);

	NTSTATUS status = STATUS_SUCCESS;
	PFLT_FILE_NAME_INFORMATION name_info = NULL;

	status = FltGetFileNameInformation(data,
		FLT_FILE_NAME_NORMALIZED
		| FLT_FILE_NAME_QUERY_DEFAULT,
		&name_info);
	if (!NT_SUCCESS(status)) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	status = FltParseFileNameInformation(name_info);
	if (!NT_SUCCESS(status)) {
		FltReleaseFileNameInformation(name_info);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	KdPrint(("[miniflt] " __FUNCTION__ " [%u] Complete to creat/open a file (%wZ)\n",
		PtrToUint(PsGetCurrentProcessId()),
		&name_info->FinalComponent));

	FltReleaseFileNameInformation(name_info);

	return FLT_POSTOP_FINISHED_PROCESSING;
}
