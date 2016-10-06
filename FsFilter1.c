/*++

Module Name:

    FsFilter1.c

Abstract:

    This is the main module of the FsFilter1 miniFilter driver.

Environment:

    Kernel mode

--*/
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


#define NT_DEVICE_NAME L"\\Device\\FSFILTER"
#define DOS_DEVICE_NAME L"\\DosDevices\\FSFILTER"

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
FsFilter1InstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
FsFilter1InstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
FsFilter1InstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
FsFilter1Unload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FsFilter1InstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
FsFilter1PostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );


EXTERN_C_END

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilter1Unload)
#pragma alloc_text(PAGE, FsFilter1InstanceQueryTeardown)
#pragma alloc_text(PAGE, FsFilter1InstanceSetup)
#pragma alloc_text(PAGE, FsFilter1InstanceTeardownStart)
#pragma alloc_text(PAGE, FsFilter1InstanceTeardownComplete)
#endif

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },
    { IRP_MJ_CLEANUP,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks
    FsFilter1Unload,                           //  MiniFilterUnload
    FsFilter1InstanceSetup,                    //  InstanceSetup
    FsFilter1InstanceQueryTeardown,            //  InstanceQueryTeardown
    FsFilter1InstanceTeardownStart,            //  InstanceTeardownStart
    FsFilter1InstanceTeardownComplete,         //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

NTSTATUS FsFilter1InstanceSetup ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                  _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!FsFilter1InstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}

NTSTATUS FsFilter1InstanceQueryTeardown ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!FsFilter1InstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}

VOID FsFilter1InstanceTeardownStart ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!FsFilter1InstanceTeardownStart: Entered\n") );
}

VOID FsFilter1InstanceTeardownComplete ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!FsFilter1InstanceTeardownComplete: Entered\n") );
}

struct driver_config_t
{
	PFLT_FILTER Filter;
	PFLT_PORT ServerPort;
	PFLT_PORT ClientPort;
	UNICODE_STRING NamePattern;
}DriverConfig;

void DeinitCommunicationPort()
{
	FltCloseCommunicationPort( DriverConfig.ServerPort );
}

NTSTATUS FilterPortConnect ( _In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
                             _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext,
                             _Outptr_result_maybenull_ PVOID *ConnectionCookie)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER( ServerPortCookie );
	UNREFERENCED_PARAMETER( ConnectionContext );
	UNREFERENCED_PARAMETER( SizeOfContext );
	UNREFERENCED_PARAMETER( ConnectionCookie );
	DriverConfig.ClientPort = ClientPort;
	return STATUS_SUCCESS;
}

VOID FilterPortDisconnect ( _In_opt_ PVOID ConnectionCookie )
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER( ConnectionCookie );
	FltCloseClientPort( DriverConfig.Filter, &DriverConfig.ClientPort );
}

NTSTATUS FilterPortMessageNotify(IN PVOID PortCookie, IN PVOID InputBuffer OPTIONAL,
                                 IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL,
                                 IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	UNREFERENCED_PARAMETER( PortCookie );
	UNREFERENCED_PARAMETER( InputBufferLength );
	UNREFERENCED_PARAMETER( OutputBuffer );
	UNREFERENCED_PARAMETER( OutputBufferLength );
	UNREFERENCED_PARAMETER( ReturnOutputBufferLength );

	RtlInitUnicodeString( &DriverConfig.NamePattern, InputBuffer );
	return STATUS_SUCCESS;
}

NTSTATUS InitCommunicationPort(_In_ PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES oa;
	PSECURITY_DESCRIPTOR sd;
	UNICODE_STRING ntUnicodeString;

	UNREFERENCED_PARAMETER( DriverObject );

	RtlInitUnicodeString( &ntUnicodeString, NT_DEVICE_NAME );
	status = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS );
	if ( !NT_SUCCESS( status ) )
    {
        return status;
	}
	InitializeObjectAttributes( &oa, &ntUnicodeString,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL, sd );
	status = FltCreateCommunicationPort( DriverConfig.Filter,
                                             &DriverConfig.ServerPort,
                                             &oa,
                                             NULL,
                                             FilterPortConnect,
                                             FilterPortDisconnect,
                                             FilterPortMessageNotify, 1 );
	FltFreeSecurityDescriptor( sd );
	return status;
}

NTSTATUS DriverEntry (_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
 
    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!DriverEntry: Entered\n") );

    status = InitCommunicationPort(DriverObject);
    if(!NT_SUCCESS(status))
    {
    	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                ("Couldn't create the device object\n") );
    	return status;
    }
    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) 
    	goto abort_driver_entry1;
    status = FltStartFiltering( gFilterHandle );

    if (!NT_SUCCESS( status ))
        goto abort_driver_entry2;
    return status;
abort_driver_entry2:
	FltUnregisterFilter( gFilterHandle );
abort_driver_entry1:
	DeinitCommunicationPort();
	return status;
}

NTSTATUS FsFilter1Unload ( _In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!FsFilter1Unload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );
    DeinitCommunicationPort();

    return STATUS_SUCCESS;
}

/**
	Основная идея - шаблон сравнения разбить на фрагменты, состоящие из известного числа символов, т.е. не содержащих '*'
	и последовательно искать эти фрагменты в проверяемом пути.
	Xwcsncmp, Xwcsstr - это стандартные wcsncmp, wcsstr (взято из исходников FreeBSD) с фиксом под знак '?'
	wcstok_star - по сути это реализация strtok_r.
	CompareUnicodePrefix - сверяет фрагмент шаблона поиска с началом подаваемой строки str. При этом, символ '?' пропускает проверку символа
	PathMatchSpec с помощью wcstok_star из шаблона выбирает следующий фрагмент и делает сверку с началом имени пути.
	Если не совпало => путь не подходит под шаблон
	Если совпало - сдвигам указатель по пути на длину проверенного фрагмента.
	И так проверяем до тех пор пока не переберем все фрагменты или пока не дойдем до конца проверяемого пути.
*/

wchar_t *wcstok_star(wchar_t *wstr, wchar_t **tsafe, int *plen)
{
	int len = 0;
	if(wstr)
		*tsafe = wstr;
	wchar_t *ret_ptr = *tsafe;
	wchar_t *ptr = ret_ptr;
	while(*ptr && *ptr != L'*')
	{
		ptr++;
		len++;
	}
	if(*ptr)
	{
		*ptr = 0;
		*tsafe = ptr + 1;
		return ret_ptr;
	}
	*plen = len;
	return NULL;
}

BOOLEAN CompareUnicodePrefix(wchar_t *prefix, wchar_t *str, int len)
{
	int i = 0;
	wchar_t *pchar = prefix;
	wchar_t *nchar = str;
	while( i < len && *pchar && *nchar)
	{
		if(*pchar != *nchar && *pchar != L'?')
			return FALSE;
		i++;
		pchar++;
		nchar++;
	}
	return (i == len || *nchar);
}

int Xwcsncmp(const wchar_t *s1, const wchar_t *s2, size_t n)
{
	if (n == 0)
		return (0);
	do {
		if ((*s1 != L'?' && *s2 != L'?') && *s1 != *s2++) {
			return (*(const unsigned int *)s1 -
			    *(const unsigned int *)--s2);
		}
		if (*s1++ == 0)
			break;
	} while (--n != 0);
	return (0);
}

wchar_t *Xwcsstr(const wchar_t * __restrict s, const wchar_t * __restrict find)
{
	wchar_t c, sc;
	size_t len;

	if ((c = *find++) != 0) {
		len = wcslen(find);
		do {
			do {
				if ((sc = *s++) == L'\0')
					return (NULL);
			} while (sc != c);
		} while (Xwcsncmp(s, find, len) != 0);
		s--;
	}
	return ((wchar_t *)s);
}

BOOLEAN PathMatchSpec(PUNICODE_STRING pattern, PUNICODE_STRING name)
{
	UNICODE_STRING tmp;	
	wchar_t *t1;
	wchar_t *tsafe_ptr = NULL;
	wchar_t *nchar = name->Buffer;
	int l = 0;
	RtlUnicodeStringInit(&tmp, pattern->Buffer);
	t1 = tmp.Buffer;
	while(TRUE)
	{
		int fragment_len = 0;
		wchar_t *pattern_fragment = wcstok_star(t1, &tsafe_ptr, &fragment_len);
		t1 = NULL;
		if(!pattern_fragment)
			break;
		nchar = wcsstr(nchar, pattern_fragment);
		if(!nchar)
			return FALSE;
		if(CompareUnicodePrefix(pattern_fragment, nchar, fragment_len) == FALSE)
			return FALSE;
		nchar += fragment_len;
		l+= fragment_len;
		if(l > name->Length)
			break;
	}
	return TRUE;
}

FLT_PREOP_CALLBACK_STATUS FsFilter1PreOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                        _Flt_CompletionContext_Outptr_ PVOID *CompletionContext )
{
    NTSTATUS ret_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!FsFilter1PreWriteOperation: Entered\n") );

    return ret_status;
}

FLT_POSTOP_CALLBACK_STATUS FsFilter1PostOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                          _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags )
{
	NTSTATUS status, ret_status = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_FILE_NAME_INFORMATION nameInfo;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilter1!FsFilter1PostWriteOperation: Entered\n") );

    status = FltGetFileNameInformation( Data,
                                        FLT_FILE_NAME_NORMALIZED |
                                        FLT_FILE_NAME_QUERY_DEFAULT,	
                                        &nameInfo );
    if (!NT_SUCCESS( status ))
        return FLT_POSTOP_FINISHED_PROCESSING;
    FltParseFileNameInformation( nameInfo );

    if((FltObjects->FileObject->WriteAccess
    		|| FltObjects->FileObject->DeleteAccess) 
    		&& PathMatchSpec(&DriverConfig.NamePattern, &nameInfo->Name))
    {
    	FltCancelIo(Data);
		ret_status = FLT_PREOP_COMPLETE;
	}
	FltReleaseFileNameInformation( nameInfo );
    return ret_status;
}
