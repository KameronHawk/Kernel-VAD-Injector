#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <fltKernel.h>

typedef unsigned char BYTE;

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

EXTERN_C NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

EXTERN_C
NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	_In_ PEPROCESS FromProcess,
	_In_ PVOID FromAddress,
	_In_ PEPROCESS ToProcess,
	_Out_ PVOID ToAddress,
	_In_ SIZE_T BufferSize,
	_In_ KPROCESSOR_MODE PreviousMode,
	_Out_ PSIZE_T NumberOfBytesCopied
);

EXTERN_C NTKERNELAPI
NTSTATUS
NTAPI
PsGetContextThread(_In_ PETHREAD Thread,
	_Inout_ PCONTEXT ThreadContext,
	_In_ KPROCESSOR_MODE Mode);

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwLockVirtualMemory(_In_ HANDLE 	ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T 	NumberOfBytesToLock,
	_In_ ULONG 	MapType
);

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwUnlockVirtualMemory(_In_ HANDLE 	ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T 	NumberOfBytesToUnlock,
	_In_ ULONG 	MapType
);

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;

EXTERN_C NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

EXTERN_C __declspec(dllimport)
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

EXTERN_C NTKERNELAPI PVOID PsGetProcessWow64Process(__in PEPROCESS Process);





//0x18 bytes (sizeof)
typedef struct _POOL_TRACKER_BIG_PAGES
{
	volatile ULONGLONG Va;                                                  //0x0
	ULONG Key;                                                              //0x8
	ULONG Pattern : 8;                                                        //0xc
	ULONG PoolType : 12;                                                      //0xc
	ULONG SlushSize : 12;                                                     //0xc
	ULONGLONG NumberOfBytes;                                                //0x10
}POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;


typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION {
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebBase;
	ULONG_PTR Reserved2;
	ULONG_PTR Reserved3;
	ULONG_PTR Reserved4;
}SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	VOID* EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	ULONGLONG Mutant;                                                       //0x8
	ULONGLONG ImageBaseAddress;                                             //0x10
	PEB_LDR_DATA* Ldr;                                                          //0x18
	ULONGLONG ProcessParameters;                                            //0x20
	ULONGLONG SubSystemData;                                                //0x28
	ULONGLONG ProcessHeap;                                                  //0x30
	ULONGLONG FastPebLock;                                                  //0x38
	ULONGLONG AtlThunkSListPtr;                                             //0x40
	ULONGLONG IFEOKey;                                                      //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ProcessPreviouslyThrottled : 1;                             //0x50
			ULONG ProcessCurrentlyThrottled : 1;                              //0x50
			ULONG ProcessImagesHotPatched : 1;                                //0x50
			ULONG ReservedBits0 : 24;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		ULONGLONG KernelCallbackTable;                                      //0x58
		ULONGLONG UserSharedInfoPtr;                                        //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	ULONGLONG ApiSetMap;                                                    //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	ULONGLONG TlsBitmap;                                                    //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	ULONGLONG ReadOnlySharedMemoryBase;                                     //0x88
	ULONGLONG SharedData;                                                   //0x90
	ULONGLONG ReadOnlyStaticServerData;                                     //0x98
	ULONGLONG AnsiCodePageData;                                             //0xa0
	ULONGLONG OemCodePageData;                                              //0xa8
	ULONGLONG UnicodeCaseTableData;                                         //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	ULONGLONG ProcessHeaps;                                                 //0xf0
	ULONGLONG GdiSharedHandleTable;                                         //0xf8
	ULONGLONG ProcessStarterHelper;                                         //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	ULONGLONG LoaderLock;                                                   //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	ULONGLONG PostProcessInitRoutine;                                       //0x230
	ULONGLONG TlsExpansionBitmap;                                           //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	ULONGLONG pShimData;                                                    //0x2d8
	ULONGLONG AppCompatInfo;                                                //0x2e0
	struct _STRING64 CSDVersion;                                            //0x2e8
	ULONGLONG ActivationContextData;                                        //0x2f8
	ULONGLONG ProcessAssemblyStorageMap;                                    //0x300
	ULONGLONG SystemDefaultActivationContextData;                           //0x308
	ULONGLONG SystemAssemblyStorageMap;                                     //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	ULONGLONG SparePointers[4];                                             //0x320
	ULONG SpareUlongs[5];                                                   //0x340
	ULONGLONG WerRegistrationData;                                          //0x358
	ULONGLONG WerShipAssertPtr;                                             //0x360
	ULONGLONG pUnused;                                                      //0x368
	ULONGLONG pImageHeaderHash;                                             //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	struct LIST_ENTRY64 TppWorkerpList;                                     //0x390
	ULONGLONG WaitOnAddressHashTable[128];                                  //0x3a0
	ULONGLONG TelemetryCoverageHeader;                                      //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
	ULONG CloudFileDiagFlags;                                               //0x7ac
	CHAR PlaceholderCompatibilityMode;                                      //0x7b0
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
	ULONGLONG LeapSecondData;                                               //0x7b8
	union
	{
		ULONG LeapSecondFlags;                                              //0x7c0
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x7c0
			ULONG Reserved : 31;                                              //0x7c0
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x7c4
} PEB64, * PPEB64;

//0x480 bytes (sizeof)
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	ULONG Mutant;                                                           //0x4
	ULONG ImageBaseAddress;                                                 //0x8
	ULONG Ldr;                                                              //0xc
	ULONG ProcessParameters;                                                //0x10
	ULONG SubSystemData;                                                    //0x14
	ULONG ProcessHeap;                                                      //0x18
	ULONG FastPebLock;                                                      //0x1c
	ULONG AtlThunkSListPtr;                                                 //0x20
	ULONG IFEOKey;                                                          //0x24
	union
	{
		ULONG CrossProcessFlags;                                            //0x28
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x28
			ULONG ProcessInitializing : 1;                                    //0x28
			ULONG ProcessUsingVEH : 1;                                        //0x28
			ULONG ProcessUsingVCH : 1;                                        //0x28
			ULONG ProcessUsingFTH : 1;                                        //0x28
			ULONG ProcessPreviouslyThrottled : 1;                             //0x28
			ULONG ProcessCurrentlyThrottled : 1;                              //0x28
			ULONG ProcessImagesHotPatched : 1;                                //0x28
			ULONG ReservedBits0 : 24;                                         //0x28
		};
	};
	union
	{
		ULONG KernelCallbackTable;                                          //0x2c
		ULONG UserSharedInfoPtr;                                            //0x2c
	};
	ULONG SystemReserved;                                                   //0x30
	ULONG AtlThunkSListPtr32;                                               //0x34
	ULONG ApiSetMap;                                                        //0x38
	ULONG TlsExpansionCounter;                                              //0x3c
	ULONG TlsBitmap;                                                        //0x40
	ULONG TlsBitmapBits[2];                                                 //0x44
	ULONG ReadOnlySharedMemoryBase;                                         //0x4c
	ULONG SharedData;                                                       //0x50
	ULONG ReadOnlyStaticServerData;                                         //0x54
	ULONG AnsiCodePageData;                                                 //0x58
	ULONG OemCodePageData;                                                  //0x5c
	ULONG UnicodeCaseTableData;                                             //0x60
	ULONG NumberOfProcessors;                                               //0x64
	ULONG NtGlobalFlag;                                                     //0x68
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
	ULONG HeapSegmentReserve;                                               //0x78
	ULONG HeapSegmentCommit;                                                //0x7c
	ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
	ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
	ULONG NumberOfHeaps;                                                    //0x88
	ULONG MaximumNumberOfHeaps;                                             //0x8c
	ULONG ProcessHeaps;                                                     //0x90
	ULONG GdiSharedHandleTable;                                             //0x94
	ULONG ProcessStarterHelper;                                             //0x98
	ULONG GdiDCAttributeList;                                               //0x9c
	ULONG LoaderLock;                                                       //0xa0
	ULONG OSMajorVersion;                                                   //0xa4
	ULONG OSMinorVersion;                                                   //0xa8
	USHORT OSBuildNumber;                                                   //0xac
	USHORT OSCSDVersion;                                                    //0xae
	ULONG OSPlatformId;                                                     //0xb0
	ULONG ImageSubsystem;                                                   //0xb4
	ULONG ImageSubsystemMajorVersion;                                       //0xb8
	ULONG ImageSubsystemMinorVersion;                                       //0xbc
	ULONG ActiveProcessAffinityMask;                                        //0xc0
	ULONG GdiHandleBuffer[34];                                              //0xc4
	ULONG PostProcessInitRoutine;                                           //0x14c
	ULONG TlsExpansionBitmap;                                               //0x150
	ULONG TlsExpansionBitmapBits[32];                                       //0x154
	ULONG SessionId;                                                        //0x1d4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
	ULONG pShimData;                                                        //0x1e8
	ULONG AppCompatInfo;                                                    //0x1ec
	struct _STRING32 CSDVersion;                                            //0x1f0
	ULONG ActivationContextData;                                            //0x1f8
	ULONG ProcessAssemblyStorageMap;                                        //0x1fc
	ULONG SystemDefaultActivationContextData;                               //0x200
	ULONG SystemAssemblyStorageMap;                                         //0x204
	ULONG MinimumStackCommit;                                               //0x208
	ULONG SparePointers[4];                                                 //0x20c
	ULONG SpareUlongs[5];                                                   //0x21c
	ULONG WerRegistrationData;                                              //0x230
	ULONG WerShipAssertPtr;                                                 //0x234
	ULONG pUnused;                                                          //0x238
	ULONG pImageHeaderHash;                                                 //0x23c
	union
	{
		ULONG TracingFlags;                                                 //0x240
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x240
			ULONG CritSecTracingEnabled : 1;                                  //0x240
			ULONG LibLoaderTracingEnabled : 1;                                //0x240
			ULONG SpareTracingBits : 29;                                      //0x240
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
	ULONG TppWorkerpListLock;                                               //0x250
	struct LIST_ENTRY32 TppWorkerpList;                                     //0x254
	ULONG WaitOnAddressHashTable[128];                                      //0x25c
	ULONG TelemetryCoverageHeader;                                          //0x45c
	ULONG CloudFileFlags;                                                   //0x460
	ULONG CloudFileDiagFlags;                                               //0x464
	CHAR PlaceholderCompatibilityMode;                                      //0x468
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
	ULONG LeapSecondData;                                                   //0x470
	union
	{
		ULONG LeapSecondFlags;                                              //0x474
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x474
			ULONG Reserved : 31;                                              //0x474
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x478
}PEB32, * PPEB32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ChpeImage : 1;                                              //0x68
			ULONG ReservedFlags5 : 2;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	struct _LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* Lock;                                                             //0x90
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
	struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	union _LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

//0x10 bytes (sizeof)
typedef struct _EWOW64PROCESS
{
	VOID* Peb;                                                              //0x0
	USHORT Machine;                                                         //0x8
	enum _SYSTEM_DLL_TYPE NtdllType;                                        //0xc
}EWOW64PROCESS, * PEWOW64PROCESS;

typedef struct _MEMORY_WORKING_SET_BLOCK {
	ULONG_PTR Protection : 5;
	ULONG_PTR ShareCount : 3;
	ULONG_PTR Shared : 1;
	ULONG_PTR Node : 3;
#ifdef _WIN64
	ULONG_PTR VirtualPage : 52;
#else
	ULONG VirtualPage : 20;
#endif
} MEMORY_WORKING_SET_BLOCK, * PMEMORY_WORKING_SET_BLOCK;

typedef struct _MEMORY_WORKING_SET_INFORMATION {
	ULONG_PTR NumberOfEntries;
	MEMORY_WORKING_SET_BLOCK WorkingSetInfo[1];
} MEMORY_WORKING_SET_INFORMATION, * PMEMORY_WORKING_SET_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


/*
*
*
*
*
*				VIRTUAL ADDRESS DESCRIPTOR ( VAD ) Structures
*
*
*
*/

//0x4 bytes (sizeof)
typedef struct _MMSECTION_FLAGS
{
	ULONG BeingDeleted : 1;                                                   //0x0
	ULONG BeingCreated : 1;                                                   //0x0
	ULONG BeingPurged : 1;                                                    //0x0
	ULONG NoModifiedWriting : 1;                                              //0x0
	ULONG FailAllIo : 1;                                                      //0x0
	ULONG Image : 1;                                                          //0x0
	ULONG Based : 1;                                                          //0x0
	ULONG File : 1;                                                           //0x0
	ULONG AttemptingDelete : 1;                                               //0x0
	ULONG PrefetchCreated : 1;                                                //0x0
	ULONG PhysicalMemory : 1;                                                 //0x0
	ULONG ImageControlAreaOnRemovableMedia : 1;                               //0x0
	ULONG Reserve : 1;                                                        //0x0
	ULONG Commit : 1;                                                         //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG WasPurged : 1;                                                      //0x0
	ULONG UserReference : 1;                                                  //0x0
	ULONG GlobalMemory : 1;                                                   //0x0
	ULONG DeleteOnClose : 1;                                                  //0x0
	ULONG FilePointerNull : 1;                                                //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG GlobalOnlyPerSession : 1;                                           //0x0
	ULONG UserWritable : 1;                                                   //0x0
	ULONG SystemVaAllocated : 1;                                              //0x0
	ULONG PreferredFsCompressionBoundary : 1;                                 //0x0
	ULONG UsingFileExtents : 1;                                               //0x0
	ULONG PageSize64K : 1;                                                    //0x0
};

//0x8 bytes (sizeof)
typedef struct _EX_FAST_REF
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONGLONG RefCnt : 4;                                                 //0x0
		ULONGLONG Value;                                                    //0x0
	};
};

//0x4 bytes (sizeof)
typedef struct _MMSECTION_FLAGS2
{
	USHORT PartitionId : 10;                                                  //0x0
	UCHAR NoCrossPartitionAccess : 1;                                         //0x2
	UCHAR SubsectionCrossPartitionReferenceOverflow : 1;                      //0x2
};

typedef struct _MM_PRIVATE_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysSet : 1;                                         //0x0
	ULONG WriteWatch : 1;                                                     //0x0
	ULONG FixedLargePageSize : 1;                                             //0x0
	ULONG ZeroFillPagesOptional : 1;                                          //0x0
	ULONG Graphics : 1;                                                       //0x0
	ULONG Enclave : 1;                                                        //0x0
	ULONG ShadowStack : 1;                                                    //0x0
	ULONG PhysicalMemoryPfnsReferenced : 1;                                   //0x0
};

//0x4 bytes (sizeof)
typedef struct _MM_GRAPHICS_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysSet : 1;                                         //0x0
	ULONG WriteWatch : 1;                                                     //0x0
	ULONG FixedLargePageSize : 1;                                             //0x0
	ULONG ZeroFillPagesOptional : 1;                                          //0x0
	ULONG GraphicsAlwaysSet : 1;                                              //0x0
	ULONG GraphicsUseCoherentBus : 1;                                         //0x0
	ULONG GraphicsNoCache : 1;                                                //0x0
	ULONG GraphicsPageProtection : 3;                                         //0x0
};

//0x4 bytes (sizeof)
typedef struct _MM_SHARED_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysClear : 1;                                       //0x0
	ULONG PrivateFixup : 1;                                                   //0x0
	ULONG HotPatchAllowed : 1;                                                //0x0
};

//0x8 bytes (sizeof)
typedef struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};

// 0x80 bytes(sizeof)
typedef struct _CONTROL_AREA
{
	struct _SEGMENT* Segment;                                               //0x0
	union
	{
		struct _LIST_ENTRY ListHead;                                        //0x8
		VOID* AweContext;                                                   //0x8
	};
	ULONGLONG NumberOfSectionReferences;                                    //0x18
	ULONGLONG NumberOfPfnReferences;                                        //0x20
	ULONGLONG NumberOfMappedViews;                                          //0x28
	ULONGLONG NumberOfUserReferences;                                       //0x30
	union
	{
		ULONG LongFlags;                                                    //0x38
		struct _MMSECTION_FLAGS Flags;                                      //0x38
	} u;                                                                    //0x38
	union
	{
		ULONG LongFlags;                                                    //0x3c
		struct _MMSECTION_FLAGS2 Flags;                                     //0x3c
	} u1;                                                                   //0x3c
	struct _EX_FAST_REF FilePointer;                                        //0x40
	volatile LONG ControlAreaLock;                                          //0x48
	ULONG ModifiedWriteCount;                                               //0x4c
	struct _MI_CONTROL_AREA_WAIT_BLOCK* WaitList;                           //0x50
	union
	{
		struct
		{
			union
			{
				ULONG NumberOfSystemCacheViews;                             //0x58
				ULONG ImageRelocationStartBit;                              //0x58
			};
			union
			{
				volatile LONG WritableUserReferences;                       //0x5c
				struct
				{
					ULONG ImageRelocationSizeIn64k : 16;                      //0x5c
					ULONG SystemImage : 1;                                    //0x5c
					ULONG CantMove : 1;                                       //0x5c
					ULONG StrongCode : 2;                                     //0x5c
					ULONG BitMap : 2;                                         //0x5c
					ULONG ImageActive : 1;                                    //0x5c
					ULONG ImageBaseOkToReuse : 1;                             //0x5c
				};
			};
			union
			{
				ULONG FlushInProgressCount;                                 //0x60
				ULONG NumberOfSubsections;                                  //0x60
				struct _MI_IMAGE_SECURITY_REFERENCE* SeImageStub;           //0x60
			};
		} e2;                                                               //0x58
	} u2;                                                                   //0x58
	struct _EX_PUSH_LOCK FileObjectLock;                                    //0x68
	volatile ULONGLONG LockedPages;                                         //0x70
	union
	{
		ULONGLONG IoAttributionContext : 61;                                  //0x78
		ULONGLONG Spare : 3;                                                  //0x78
		ULONGLONG ImageCrossPartitionCharge;                                //0x78
		ULONGLONG CommittedPageCount : 36;                                    //0x78
	} u3;                                                                   //0x78
}COONTROL_AREA, * PCONTROL_AREA;

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS2
{
	ULONG FileOffset : 24;                                                    //0x0
	ULONG Large : 1;                                                          //0x0
	ULONG TrimBehind : 1;                                                     //0x0
	ULONG Inherit : 1;                                                        //0x0
	ULONG NoValidationNeeded : 1;                                             //0x0
	ULONG PrivateDemandZero : 1;                                              //0x0
	ULONG Spare : 3;                                                          //0x0
};

//0x8 bytes (sizeof)
typedef struct _MI_VAD_SEQUENTIAL_INFO
{
	ULONGLONG Length : 12;                                                    //0x0
	ULONGLONG Vpn : 52;                                                       //0x0
};

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemory : 1;                                                  //0x0
};

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS1
{
	ULONG CommitCharge : 31;                                                  //0x0
	ULONG MemCommit : 1;                                                      //0x0
};

//0x40 bytes (sizeof)
typedef struct _MMVAD_SHORT
{
	union
	{
		struct
		{
			struct _MMVAD_SHORT* NextVad;                                   //0x0
			VOID* ExtraCreateInfo;                                          //0x8
		};
		struct _RTL_BALANCED_NODE VadNode;                                  //0x0
	};
	ULONG StartingVpn;                                                      //0x18
	ULONG EndingVpn;                                                        //0x1c
	UCHAR StartingVpnHigh;                                                  //0x20
	UCHAR EndingVpnHigh;                                                    //0x21
	UCHAR CommitChargeHigh;                                                 //0x22
	UCHAR SpareNT64VadUChar;                                                //0x23
	LONG ReferenceCount;                                                    //0x24
	struct _EX_PUSH_LOCK PushLock;                                          //0x28
	union
	{
		ULONG LongFlags;                                                    //0x30
		struct _MMVAD_FLAGS VadFlags;                                       //0x30
		struct _MM_PRIVATE_VAD_FLAGS PrivateVadFlags;                       //0x30
		struct _MM_GRAPHICS_VAD_FLAGS GraphicsVadFlags;                     //0x30
		struct _MM_SHARED_VAD_FLAGS SharedVadFlags;                         //0x30
		volatile ULONG VolatileVadLong;                                     //0x30
	} u;                                                                    //0x30
	union
	{
		ULONG LongFlags1;                                                   //0x34
		struct _MMVAD_FLAGS1 VadFlags1;                                     //0x34
	} u1;                                                                   //0x34
	struct _MI_VAD_EVENT_BLOCK* EventList;                                  //0x38
}MMVAD_SHORT, * PMMVAD_SHORT;

//0x88 bytes (sizeof)
typedef struct _MMVAD
{
	struct _MMVAD_SHORT Core;                                               //0x0
	union
	{
		ULONG LongFlags2;                                                   //0x40
		volatile struct _MMVAD_FLAGS2 VadFlags2;                            //0x40
	} u2;                                                                   //0x40
	struct _SUBSECTION* Subsection;                                         //0x48
	struct _MMPTE* FirstPrototypePte;                                       //0x50
	struct _MMPTE* LastContiguousPte;                                       //0x58
	struct _LIST_ENTRY ViewLinks;                                           //0x60
	struct _EPROCESS* VadsProcess;                                          //0x70
	union
	{
		struct _MI_VAD_SEQUENTIAL_INFO SequentialVa;                        //0x78
		struct _MMEXTEND_INFO* ExtendedInfo;                                //0x78
	} u4;                                                                   //0x78
	struct _FILE_OBJECT* FileObject;                                        //0x80
}MMVAD, * PMMVAD;

typedef struct _MM_AVL_NODE // Size=24
{
	struct _MM_AVL_NODE* LeftChild; // Size=8 Offset=0
	struct _MM_AVL_NODE* RightChild; // Size=8 Offset=8

	union ___unnamed1666 // Size=8
	{
		struct
		{
			__int64 Balance : 2; // Size=8 Offset=0 BitOffset=0 BitCount=2
		};
		struct _MM_AVL_NODE* Parent; // Size=8 Offset=0
	} u1;
} MM_AVL_NODE, * PMM_AVL_NODE, * PMMADDRESS_NODE;

typedef struct _RTL_AVL_TREE // Size=8
{
	PMM_AVL_NODE BalancedRoot;
	void* NodeHint;
	unsigned __int64 NumberGenericTableElements;
} RTL_AVL_TREE, * PRTL_AVL_TREE, MM_AVL_TABLE, * PMM_AVL_TABLE;


typedef struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Dirty1 : 1;                                                     //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Accessed : 1;                                                   //0x0
	ULONGLONG Dirty : 1;                                                      //0x0
	ULONGLONG LargePage : 1;                                                  //0x0
	ULONGLONG Global : 1;                                                     //0x0
	ULONGLONG CopyOnWrite : 1;                                                //0x0
	ULONGLONG Unused : 1;                                                     //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG ReservedForHardware : 4;                                        //0x0
	ULONGLONG ReservedForSoftware : 4;                                        //0x0
	ULONGLONG WsleAge : 4;                                                    //0x0
	ULONGLONG WsleProtection : 3;                                             //0x0
	ULONGLONG NoExecute : 1;                                                  //0x0
};

typedef struct _MMPTE
{
	union
	{
		ULONG_PTR Long;
		_MMPTE_HARDWARE Hard;
	} u;
} MMPTE;
typedef MMPTE* PMMPTE;

EXTERN_C NTSYSAPI
PVOID
NTAPI
RtlAvlRemoveNode(
	IN PRTL_AVL_TREE pTree,
	IN PMMADDRESS_NODE pNode
);
EXTERN_C NTSYSAPI
NTSTATUS
NTAPI
MmMarkPhysicalMemoryAsBad(IN PPHYSICAL_ADDRESS StartAddress,
	IN OUT PLARGE_INTEGER NumberOfBytes);

EXTERN_C NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PLONG OldAccessProtection);

EXTERN_C NTSYSAPI
NTSTATUS 
NTAPI 
ZwQueryInformationThread(
	_In_      HANDLE          ThreadHandle,
	_In_      THREADINFOCLASS ThreadInformationClass,
	_In_      PVOID           ThreadInformation,
	_In_      ULONG           ThreadInformationLength,
	_Out_opt_ PULONG          ReturnLength
);






typedef struct _SYSTEM_MODULE {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

//0x480 bytes (sizeof)
typedef struct __KTHREAD__
{
	struct _DISPATCHER_HEADER Header;                                       //0x0
	VOID* SListFaultAddress;                                                //0x18
	ULONGLONG QuantumTarget;                                                //0x20
	VOID* InitialStack;                                                     //0x28
	VOID* volatile StackLimit;                                              //0x30
	VOID* StackBase;                                                        //0x38
	ULONGLONG ThreadLock;                                                   //0x40
	volatile ULONGLONG CycleTime;                                           //0x48
	ULONG CurrentRunTime;                                                   //0x50
	ULONG ExpectedRunTime;                                                  //0x54
	VOID* KernelStack;                                                      //0x58
	struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
	struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
	void* notneeded;                       //0x70
	volatile UCHAR Running;                                                 //0x71
	UCHAR Alerted[2];                                                       //0x72
	union
	{
		struct
		{
			ULONG AutoBoostActive : 1;                                        //0x74
			ULONG ReadyTransition : 1;                                        //0x74
			ULONG WaitNext : 1;                                               //0x74
			ULONG SystemAffinityActive : 1;                                   //0x74
			ULONG Alertable : 1;                                              //0x74
			ULONG UserStackWalkActive : 1;                                    //0x74
			ULONG ApcInterruptRequest : 1;                                    //0x74
			ULONG QuantumEndMigrate : 1;                                      //0x74
			ULONG UmsDirectedSwitchEnable : 1;                                //0x74
			ULONG TimerActive : 1;                                            //0x74
			ULONG SystemThread : 1;                                           //0x74
			ULONG ProcessDetachActive : 1;                                    //0x74
			ULONG CalloutActive : 1;                                          //0x74
			ULONG ScbReadyQueue : 1;                                          //0x74
			ULONG ApcQueueable : 1;                                           //0x74
			ULONG ReservedStackInUse : 1;                                     //0x74
			ULONG UmsPerformingSyscall : 1;                                   //0x74
			ULONG TimerSuspended : 1;                                         //0x74
			ULONG SuspendedWaitMode : 1;                                      //0x74
			ULONG SuspendSchedulerApcWait : 1;                                //0x74
			ULONG CetUserShadowStack : 1;                                     //0x74
			ULONG BypassProcessFreeze : 1;                                    //0x74
			ULONG Reserved : 10;                                              //0x74
		};
		LONG MiscFlags;                                                     //0x74
	};
	union
	{
		struct
		{
			ULONG ThreadFlagsSpare : 2;                                       //0x78
			ULONG AutoAlignment : 1;                                          //0x78
			ULONG DisableBoost : 1;                                           //0x78
			ULONG AlertedByThreadId : 1;                                      //0x78
			ULONG QuantumDonation : 1;                                        //0x78
			ULONG EnableStackSwap : 1;                                        //0x78
			ULONG GuiThread : 1;                                              //0x78
			ULONG DisableQuantum : 1;                                         //0x78
			ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
			ULONG DeferPreemption : 1;                                        //0x78
			ULONG QueueDeferPreemption : 1;                                   //0x78
			ULONG ForceDeferSchedule : 1;                                     //0x78
			ULONG SharedReadyQueueAffinity : 1;                               //0x78
			ULONG FreezeCount : 1;                                            //0x78
			ULONG TerminationApcRequest : 1;                                  //0x78
			ULONG AutoBoostEntriesExhausted : 1;                              //0x78
			ULONG KernelStackResident : 1;                                    //0x78
			ULONG TerminateRequestReason : 2;                                 //0x78
			ULONG ProcessStackCountDecremented : 1;                           //0x78
			ULONG RestrictedGuiThread : 1;                                    //0x78
			ULONG VpBackingThread : 1;                                        //0x78
			ULONG ThreadFlagsSpare2 : 1;                                      //0x78
			ULONG EtwStackTraceApcInserted : 8;                               //0x78
		};
		volatile LONG ThreadFlags;                                          //0x78
	};
	volatile UCHAR Tag;                                                     //0x7c
	UCHAR SystemHeteroCpuPolicy;                                            //0x7d
	UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
	UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
	union
	{
		struct
		{
			UCHAR RunningNonRetpolineCode : 1;                                //0x7f
			UCHAR SpecCtrlSpare : 7;                                          //0x7f
		};
		UCHAR SpecCtrl;                                                     //0x7f
	};
	ULONG SystemCallNumber;                                                 //0x80
	ULONG ReadyTime;                                                        //0x84
	VOID* FirstArgument;                                                    //0x88
	struct _KTRAP_FRAME* TrapFrame;                                         //0x90
	union
	{
		struct _KAPC_STATE ApcState;                                        //0x98
		struct
		{
			UCHAR ApcStateFill[43];                                         //0x98
			CHAR Priority;                                                  //0xc3
			ULONG UserIdealProcessor;                                       //0xc4
		};
	};
	volatile LONGLONG WaitStatus;                                           //0xc8
	struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
	union
	{
		struct _LIST_ENTRY WaitListEntry;                                   //0xd8
		struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
	};
	struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
	VOID* Teb;                                                              //0xf0
}MY_KTHREAD, * PMY_PKTHREAD;

//0x1838 bytes (sizeof)
typedef struct _TEB
{
	struct _NT_TIB NtTib;                                                   //0x0
}TEB, *PTEB;

EXTERN_C NTKERNELAPI PVOID NTAPI PsGetThreadTeb(PETHREAD Thread);

EXTERN_C NTKERNELAPI NTSTATUS NTAPI ZwOpenThread(OUT PHANDLE hThread,
	IN ACCESS_MASK AccessMask,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId);

EXTERN_C
NTKERNELAPI 
NTSTATUS 
NtQueryInformationThread(
	          HANDLE          ThreadHandle,
	          THREADINFOCLASS ThreadInformationClass,
			  PVOID           ThreadInformation,
	          ULONG           ThreadInformationLength,
			  PULONG          ReturnLength
);



/*
*
*
*
*							NON-EXPORTED FUNCTION TYPE DEFINITIONS
*
*
*
*/
typedef NTSTATUS(__fastcall* PspGetContextThreadInternal)(PETHREAD, PCONTEXT, int, int, int);	// PspGetContextThreadInternal

typedef NTSTATUS(__fastcall* PspSetcontextThreadInternal)(PETHREAD, PCONTEXT, int, int, int);	// PspSetContextThreadInternal

typedef NTSTATUS(__fastcall* PsSuspendThread)(PETHREAD, OUT PLONG OPTIONAL);					// PsSuspendThread

typedef NTSTATUS(__fastcall* PsResumeThread)(PETHREAD, OUT PLONG OPTIONAL);						// PsResumeThread

typedef PVOID(__fastcall* RtlImageDirectoryEntryToData)(PVOID ImageBase, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size);

typedef NTSTATUS(__fastcall* MiResetVirtualMemory)(IN PVOID StartingAddress, IN PVOID EndingAddress, IN PMMVAD Vad, IN PEPROCESS Process);

