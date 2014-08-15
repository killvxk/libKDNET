
#define UINT64 uint64_t
#define ULONG64 uint64_t
#define ULONG uint32_t
#define LONG int32_t
#define USHORT uint16_t
#define UCHAR uint8_t


enum{
	PACKET_TYPE_UNUSED = 0,
 	PACKET_TYPE_KD_STATE_CHANGE32 = 1,
 	PACKET_TYPE_KD_STATE_MANIPULATE = 2,
 	PACKET_TYPE_KD_DEBUG_IO = 3,
 	PACKET_TYPE_KD_ACKNOWLEDGE = 4,
 	PACKET_TYPE_KD_RESEND = 5,
 	PACKET_TYPE_KD_RESET = 6,
 	PACKET_TYPE_KD_STATE_CHANGE64 = 7,
 	PACKET_TYPE_KD_POLL_BREAKIN = 8,
 	PACKET_TYPE_KD_TRACE_IO = 9,
 	PACKET_TYPE_KD_CONTROL_REQUEST = 10,
 	PACKET_TYPE_KD_FILE_IO = 11,
 	PACKET_TYPE_MAX = 12,
};

enum KD_STATE_CHANGE_API_NUMBER{
DbgKdExceptionStateChange = 0x00003030,
DbgKdLoadSymbolsStateChange = 0x00003031,
DbgKdCommandStringStateChange = 0x00003032
};


#define DbgKdMinimumManipulate              0x00003130
#define DbgKdReadVirtualMemoryApi           0x00003130
#define DbgKdWriteVirtualMemoryApi          0x00003131
#define DbgKdGetContextApi                  0x00003132
#define DbgKdSetContextApi                  0x00003133
#define DbgKdWriteBreakPointApi             0x00003134
#define DbgKdRestoreBreakPointApi           0x00003135
#define DbgKdContinueApi                    0x00003136
#define DbgKdReadControlSpaceApi            0x00003137
#define DbgKdWriteControlSpaceApi           0x00003138
#define DbgKdReadIoSpaceApi                 0x00003139
#define DbgKdWriteIoSpaceApi                0x0000313A
#define DbgKdRebootApi                      0x0000313B
#define DbgKdContinueApi2                   0x0000313C
#define DbgKdReadPhysicalMemoryApi          0x0000313D
#define DbgKdWritePhysicalMemoryApi         0x0000313E
#define DbgKdQuerySpecialCallsApi           0x0000313F
#define DbgKdSetSpecialCallApi              0x00003140
#define DbgKdClearSpecialCallsApi           0x00003141
#define DbgKdSetInternalBreakPointApi       0x00003142
#define DbgKdGetInternalBreakPointApi       0x00003143
#define DbgKdReadIoSpaceExtendedApi         0x00003144
#define DbgKdWriteIoSpaceExtendedApi        0x00003145
#define DbgKdGetVersionApi                  0x00003146
#define DbgKdWriteBreakPointExApi           0x00003147
#define DbgKdRestoreBreakPointExApi         0x00003148
#define DbgKdCauseBugCheckApi               0x00003149
#define DbgKdSwitchProcessor                0x00003150
#define DbgKdPageInApi                      0x00003151
#define DbgKdReadMachineSpecificRegister    0x00003152
#define DbgKdWriteMachineSpecificRegister   0x00003153
#define OldVlm1                             0x00003154
#define OldVlm2                             0x00003155
#define DbgKdSearchMemoryApi                0x00003156
#define DbgKdGetBusDataApi                  0x00003157
#define DbgKdSetBusDataApi                  0x00003158
#define DbgKdCheckLowMemoryApi              0x00003159
#define DbgKdClearAllInternalBreakpointsApi 0x0000315A
#define DbgKdFillMemoryApi                  0x0000315B
#define DbgKdQueryMemoryApi                 0x0000315C
#define DbgKdSwitchPartition                0x0000315D
#define DbgKdMaximumManipulate              0x0000315E
//New in v2
#define DbgKdGetRegister					0x0000315F


#pragma pack(push)
#pragma pack(1)
typedef struct _DBGKD_LOAD_SYMBOLS64
{
     ULONG PathNameLength;
     UINT64 BaseOfDll;
     UINT64 ProcessId;
     ULONG CheckSum;
     ULONG SizeOfImage;
     UCHAR UnloadSymbols;
} DBGKD_LOAD_SYMBOLS64, *PDBGKD_LOAD_SYMBOLS64;

typedef struct _KDNET_PACKET_HEADER
{
	uint32_t Signature;
	uint8_t ProtocolVersion;
    uint8_t Canal;
    //CipheredData;
} KDNET_PACKET_HEADER, *PKDNET_PACKET_HEADER;

typedef struct _KD_PACKET_HEADER{
	uint32_t Signature;
	uint16_t PacketType;
	uint16_t DataSize;
	uint32_t PacketID;
	uint32_t Checksum;
	union{
		uint8_t PacketBody[1];
		uint32_t ApiNumber;
	};
	
}KD_PACKET_HEADER, *PKD_PACKET_HEADER;


typedef struct _EXCEPTION_RECORD64
{
     LONG ExceptionCode;
     ULONG ExceptionFlags;
     UINT64 ExceptionRecord;
     UINT64 ExceptionAddress;
     ULONG NumberParameters;
     ULONG __unusedAlignment;
     UINT64 ExceptionInformation[15];
} EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;

typedef struct _DBGKM_EXCEPTION64
{
    EXCEPTION_RECORD64 ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION64, *PDBGKM_EXCEPTION64;

typedef struct _DBGKD_WAIT_STATE_CHANGE64
{
    ULONG NewState;
    USHORT ProcessorLevel;
    USHORT Processor;
    ULONG NumberProcessors;
    ULONG64 Thread;
    ULONG64 ProgramCounter;
    union
    {
        DBGKM_EXCEPTION64 Exception;
        DBGKD_LOAD_SYMBOLS64 LoadSymbols;
    } u;
} DBGKD_WAIT_STATE_CHANGE64, *PDBGKD_WAIT_STATE_CHANGE64;

typedef struct _DBGKD_GET_VERSION_API64
{
	uint8_t unknown[28];
	ULONG64 KernelImageBase;
	ULONG64 PsLoadedModuleList;
	ULONG64 DebuggerDataList;
} DBGKD_GET_VERSION_API64, *PDBGKD_GET_VERSION_API64;


typedef struct _DBGKD_READ_MEMORY64
{
    ULONG64 TargetBaseAddress;
    ULONG TransferCount;
    ULONG ActualBytesRead;
    uint8_t unknown[24];
    uint8_t Data[1];
} DBGKD_READ_MEMORY64, *PDBGKD_READ_MEMORY64;

#define NTSTATUS uint32_t

typedef struct _DBGKD_GET_REGISTER64{
	ULONG ApiNumber;
	uint8_t unknown[172];
	ULONG64 rax;
	ULONG64 rcx;
	ULONG64 rdx;
	ULONG64 rbx;
	ULONG64 rsp;
	ULONG64 rbp;
	ULONG64 rsi;
	ULONG64 rdi;
	ULONG64 r8;
	ULONG64 r9;
	ULONG64 r10;
	ULONG64 r11;
	ULONG64 r12;
	ULONG64 r13;
	ULONG64 r14;
	ULONG64 r15;
	ULONG64 rip;
	
}DBGKD_GET_REGISTER64,*PBGKD_GET_REGISTER64;

typedef struct _DBGKD_MANIPULATE_STATE64
{
    ULONG ApiNumber;
    USHORT ProcessorLevel;
    USHORT Processor;
    NTSTATUS ReturnStatus;
    uint8_t unknown[4];//TODO: what is it ?
    union
    {
        DBGKD_READ_MEMORY64 ReadMemory;
        /*DBGKD_WRITE_MEMORY64 WriteMemory;
        DBGKD_GET_CONTEXT GetContext;
        DBGKD_SET_CONTEXT SetContext;
        DBGKD_WRITE_BREAKPOINT64 WriteBreakPoint;
        DBGKD_RESTORE_BREAKPOINT RestoreBreakPoint;
        DBGKD_CONTINUE Continue;
        DBGKD_CONTINUE2 Continue2;
        DBGKD_READ_WRITE_IO64 ReadWriteIo;
        DBGKD_READ_WRITE_IO_EXTENDED64 ReadWriteIoExtended;
        DBGKD_QUERY_SPECIAL_CALLS QuerySpecialCalls;
        DBGKD_SET_SPECIAL_CALL64 SetSpecialCall;
        DBGKD_SET_INTERNAL_BREAKPOINT64 SetInternalBreakpoint;
        DBGKD_GET_INTERNAL_BREAKPOINT64 GetInternalBreakpoint;
        DBGKD_GET_VERSION64 GetVersion64;
        DBGKD_BREAKPOINTEX BreakPointEx;
        DBGKD_READ_WRITE_MSR ReadWriteMsr;
        DBGKD_SEARCH_MEMORY SearchMemory;
        DBGKD_GET_SET_BUS_DATA GetSetBusData;
        DBGKD_FILL_MEMORY FillMemory;
        DBGKD_QUERY_MEMORY QueryMemory;
        DBGKD_SWITCH_PARTITION SwitchPartition;*/
    } u;
} DBGKD_MANIPULATE_STATE64, *PDBGKD_MANIPULATE_STATE64;
#pragma pack(pop)
