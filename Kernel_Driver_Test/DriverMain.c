#include <ntifs.h>
#include <ntstrsafe.h>
/*
* OriginalApcEnvironment(default environment):APC should be executed in the target thread's original environment. 
                                              This means that the APC will execute in the context of the target thread, 
											  regardless of whether the target thread is in the suspended, waiting, or other state.

* AttachApcEnvironment:If another thread is associated with the target thread via the KeAttachProcess or KeAttachThread function,
                       and you want to execute APC during that association, then APC should execute in AttachApcEnvironment. 
					   This is often used for debugging or other situations where you need to interact deeply with another thread or process.

*CurrentApcEnvironment:The value represents the current APC environment. 
                       If the current thread is associated with another thread or process via KeAttachThread or KeAttachProcess,
					   then CurrentApcEnvironment will be AttachApcEnvironment. Otherwise, it will be OriginalApcEnvironment.

*InsertApcEnvironment:This environment is used to indicate that the APC should be executed in the environment in which it is inserted.
                      In general, this is similar to OriginalApcEnvironment, but it is specifically designed for those
					  cases where an APC needs to be inserted ina specific context.
*/
typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,	
	AttachApcEnvironment,	
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;


typedef VOID(*PKNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);

typedef VOID(*PKKERNEL_ROUTINE) (
	IN struct _KAPC* Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRountine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
	);

typedef VOID(*PKRUNDOWN_ROUNTINE)(
	IN struct _KAPC* Apc
	);

VOID KeInitializeApc(
	__out PKAPC Apc,
	__in PKTHREAD Thread,
	__in KAPC_ENVIRONMENT Environment,
	__in PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUNTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ProcessorMode,
	_In_opt_ PVOID NormalContext
);

BOOLEAN KeInsertQueueApc(
	__inout PKAPC Apc,
	_In_opt_  PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	__in KPRIORITY Increment
);


//VOID KernelApcCallBack(
//	IN struct _KAPC* Apc,
//	IN OUT PKNORMAL_ROUTINE* NormalRountine,
//	IN OUT PVOID* NormalContext,
//	IN OUT PVOID* SystemArgument1,
//	IN OUT PVOID* SystemArgument2
//) {
//
//}

//VOID KernelApcRoutine(
//	IN struct _KAPC* Apc,
//	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
//	IN OUT PVOID* NormalContext,
//	IN OUT PVOID* SystemArgument1,
//	IN OUT PVOID* SystemArgument2
//) {
//	// Call LoadLibraryW to load dll to target process
//	PVOID pDllPath = *NormalContext;
//	PVOID hModule = NULL;
//
//	// ���û�ģʽ�л���Ŀ����̵ĵ�ַ�ռ�
//	KeStackAttachProcess(PsGetCurrentProcess(), NULL);
//	hModule = LoadLibraryW((LPCWSTR)pDllPath);
//	KeUnstackDetachProcess(NULL);
//
//	// �ͷ�֮ǰ������ڴ�
//	ExFreePoolWithTag(pDllPath, 'DLLP');
//}
//
//NTSTATUS InjectDll(PDRIVER_OBJECT pDriver, PWCHAR DllPath, HANDLE ProcessId) {
//	NTSTATUS Status = STATUS_UNSUCCESSFUL;
//	PEPROCESS TargetProcess = NULL;
//	PVOID pDllPath = NULL;
//	PKAPC pApc = NULL;
//
//	// ��ȡĿ����̵�EPROCESS�ṹ
//	Status = PsLookupProcessByProcessId(ProcessId, &TargetProcess);
//	if (!NT_SUCCESS(Status)) {
//		return Status;
//	}
//
//	// ��Ŀ����̵ĵ�ַ�ռ��з����ڴ��Դ��DLL·��
//	pDllPath = ExAllocatePoolWithTag(NonPagedPool, sizeof(WCHAR) * (wcslen(DllPath) + 1), 'DLLP');
//	if (!pDllPath) {
//		ObDereferenceObject(TargetProcess);
//		return STATUS_INSUFFICIENT_RESOURCES;
//	}
//
//	// ����DLL·����������ڴ�
//	RtlCopyMemory(pDllPath, DllPath, sizeof(WCHAR) * (wcslen(DllPath) + 1));
//
//	// ����APC�ṹ
//	pApc = ExAllocatePool(NonPagedPool, sizeof(PKAPC));
//	if (!pApc) {
//		ExFreePoolWithTag(pDllPath, 'DLLP');
//		ObDereferenceObject(TargetProcess);
//		return STATUS_INSUFFICIENT_RESOURCES;
//	}
//
//	// ��ʼ��APC�ṹ
//	KeInitializeApc(pApc,
//		PsGetCurrentThread(),
//		OriginalApcEnvironment,
//		(PKKERNEL_ROUTINE)KernelApcRoutine,
//		NULL,
//		(PKNORMAL_ROUTINE)LoadLibraryW,
//		UserMode,
//		pDllPath);
//
//	// ����APC��Ŀ���̵߳Ķ�����
//	KeInsertQueueApc(pApc, NULL, NULL, 0);
//
//	// ������Դ
//	ObDereferenceObject(TargetProcess);
//
//	return STATUS_SUCCESS;
//}

VOID DriverUnload(PDRIVER_OBJECT pDriver) {

}

NTSTATUS GetProcessIdByName(PCWSTR ProcessName, PVOID* ProcessId) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;
	WCHAR ProcessImageName[256] = { 0 };

	// ö�����н���
	for (Process = PsInitialSystemProcess; Process != NULL; Process = PsGetNextProcess(Process)) {
		// ��ȡ���̾��
		Status = ObOpenObjectByPointer(Process, 0, NULL, 0, NULL, KernelMode, &ProcessHandle);
		if (!NT_SUCCESS(Status)) {
			continue;
		}

		// ��ȡ����ӳ������
		Status = SeQueryInformationProcessToken(ProcessHandle, ProcessImageNameLength, ProcessImageName, 256 * sizeof(WCHAR));
		if (NT_SUCCESS(Status)) {
			// �Ƚ�ӳ������
			if (RtlCompareUnicodeString(&ProcessImageName, ProcessName, TRUE) == 0) {
				*ProcessId = (PVOID)PsGetProcessId(Process);
				Status = STATUS_SUCCESS;
				break;
			}
		}

		// �رս��̾��
		ObDereferenceObject(ProcessHandle);
	}

	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg) {

	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE ProcessId = 0;

	// �������Ѿ�����һ����Ч�Ľ���ID��DLL·��
	Status = GetProcessIdByName(L"targetprocess.exe", &ProcessId);
	Status = InjectDll(pDriver, L"C:\\Users\\13984\\Desktop\\Test.dll", ProcessId);

	pDriver->DriverUnload = DriverUnload;
	return Status;
}