#include <ntifs.h>
#include <ntddk.h> 
#include <intrin.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 11,

} SYSTEM_INFORMATION_CLASS;

constexpr auto IA32_EFER_MSR = 0xC0000080;
constexpr auto WINDOWS_1803 = 17134;
constexpr auto WINDOWS_1809 = 17763;
constexpr auto WINDOWS_1903 = 18362;
constexpr auto WINDOWS_1909 = 18363;
constexpr auto WINDOWS_2004 = 19041;
constexpr auto WINDOWS_20H2 = 19569;
constexpr auto WINDOWS_21H1 = 20180;

//0x7c8 bytes (sizeof)
struct _PEB
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
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	struct _PEB_LDR_DATA* Ldr;                                              //0x18
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
	VOID* IFEOKey;                                                          //0x48
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
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SharedData;                                                       //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
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
	VOID(*PostProcessInitRoutine)();                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	struct _UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	VOID* SparePointers[4];                                                 //0x320
	ULONG SpareUlongs[5];                                                   //0x340
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pUnused;                                                          //0x368
	VOID* pImageHeaderHash;                                                 //0x370
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
	struct _LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[128];                                      //0x3a0
	VOID* TelemetryCoverageHeader;                                          //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
	ULONG CloudFileDiagFlags;                                               //0x7ac
	CHAR PlaceholderCompatibilityMode;                                      //0x7b0
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
	struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
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
};

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;
	VOID* ExceptionTable;
	ULONG ExceptionTableSize;
	VOID* GpValue;
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG SizeOfImage;
	struct _UNICODE_STRING FullDllName;
	struct _UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	union
	{
		USHORT SignatureLevel : 4;
		USHORT SignatureType : 3;
		USHORT Unused : 9;
		USHORT EntireField;
	} u1;
	VOID* SectionPointer;
	ULONG CheckSum;
	ULONG CoverageSectionSize;
	VOID* CoverageSection;
	VOID* LoadedImports;
	VOID* Spare;
	ULONG SizeOfImageNotRounded;
	ULONG TimeDateStamp;
}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef union _CR3
{
	ULONG64 Value;

	struct
	{
		ULONG64 Reserved1 : 3;
		ULONG64 PageLevelWriteThrough : 1;
		ULONG64 PageLevelCacheDisable : 1;
		ULONG64 Reserved2 : 7;
		ULONG64 AddressOfPageDirectory : 36;
		ULONG64 Reserved3 : 16;
	};

} CR3, *PCR3;


typedef union _IA32_EFER
{
	ULONG64 Value;

	struct
	{
		ULONG64 SyscallEnable : 1;
		ULONG64 Reserved1 : 7;
		ULONG64 Ia32eModeEnable : 1;
		ULONG64 Reserved2 : 1;
		ULONG64 Ia32eModeActive : 1;
		ULONG64 ExecuteDisable : 1;
		ULONG64 Reserved3 : 52;
	};

}IA32_EFER, *PIA32_EFER;

typedef struct _CR4
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 VirtualModeExtensions : 1;
			ULONG64 ProtectedModeVirtualInterrupts : 1;
			ULONG64 TimestampDisable : 1;
			ULONG64 DebuggingExtensions : 1;
			ULONG64 PageSizeExtensions : 1;
			ULONG64 PhysicalAddressExtension : 1;
			ULONG64 MachineCheckEnable : 1;
			ULONG64 PageGlobalEnable : 1;
			ULONG64 PerformanceMonitoringCounterEnable : 1;
			ULONG64 OsFxsaveFxrstorSupport : 1;
			ULONG64 OsXmmExceptionSupport : 1;
			ULONG64 UsermodeInstructionPrevention : 1;
			ULONG64 Reserved1 : 1;
			ULONG64 VmxEnable : 1;
			ULONG64 SmxEnable : 1;
			ULONG64 Reserved2 : 1;
			ULONG64 FsGsBaseEnable : 1;
			ULONG64 PcidEnable : 1;
			ULONG64 OsXsave : 1;
			ULONG64 Reserved3 : 1;
			ULONG64 SmepEnable : 1;
			ULONG64 SmapEnable : 1;
			ULONG64 ProtectionKeyEnable : 1;
		};
	};
} CR4, * PCR4;

typedef union _CR0
{
	ULONG64 Value;

	struct
	{
		ULONG64 ProtectionEnable : 1;
		ULONG64 MonitorCoprocessor : 1;
		ULONG64 EmulateFpu : 1;
		ULONG64 TaskSwitched : 1;
		ULONG64 ExtensionType : 1;
		ULONG64 NumericError : 1;
		ULONG64 Reserved1 : 10;
		ULONG64 WriteProtect : 1;
		ULONG64 Reserved2 : 1;
		ULONG64 AlignmentMask : 1;
		ULONG64 Reserved3 : 10;
		ULONG64 NotWriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 PagingEnable : 1;
		ULONG64 Reserved4 : 32;
	};

} CR0, * PCR0;

//0x120 bytes (sizeof)
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
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PML4E
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
	};
} PML4E, * PPML4E;
static_assert(sizeof(PML4E) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PDPTE
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
	};
} PDPTE, * PPDPTE;
static_assert(sizeof(PDPTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PDE
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
	};
} PDE, * PPDE;
static_assert(sizeof(PDE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PTE
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Dirty : 1;
			ULONG64 PageAccessType : 1;
			ULONG64 Global : 1;
			ULONG64 Ignored2 : 3;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 7;
			ULONG64 ProtectionKey : 4;
			ULONG64 ExecuteDisable : 1;
		};
	};
} PTE, * PPTE;
static_assert(sizeof(PTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

enum _PAGE_SIZE
{
	_4kbPage, 
	_2mbPage, 
	_1gbPage 
};

typedef struct _PAGE_TABLE_INFO
{
	PPTE Pte;
	PPDE Pde;
	PPDPTE Pdpte;
	PPML4E Pml4e;
	_PAGE_SIZE PageSize;
}PAGE_TABLE_INFO, * PPAGE_TABLE_INFO;

//0x58 bytes (sizeof)
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
}PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef union _VIRTUAL_ADDRESS
{
	ULONG64 Value;

	// 4Kb Pages 

	struct
	{
		ULONG64 Offset4Kb : 12;
		ULONG64 PtIndex : 9;
		ULONG64 PdIndex : 9;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};

	// 2mb Pages 

	struct
	{
		ULONG64 Offset2mb : 21;
		ULONG64 PdIndex : 9;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};

	// 1Gb Pages 

	struct
	{
		ULONG64 Offset1Gb : 30;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};

}VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;

typedef struct _PTE_HIERARCHY
{
	PPTE Pte;
	PPDE Pde;
	PPDPTE Pdpte;
	PPML4E Pml4e;
}PTE_HIERARCHY, * PPTE_HIERARCHY;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD Unload;

ULONG64 GetPhysicalAddress(
	ULONG64 VirtualAddress, 
	HANDLE Pid 
);

ULONG64 GetUserDirOffset(
	VOID
);

PVOID GetProcessCr3(
	HANDLE Pid
);

VOID QueryPagingInfo(
	VOID
);

template <typename T>
auto ReadPhysicalMemory(
	T* TargetAddress
) -> T;

template <typename T>
auto GetVirtualAddress(
	ULONG64 PhysicalAddress
) -> T;

template <typename T>
auto ReadKernelMemory(
	ULONG64 Address
)-> T;

VOID LocateData(
	VOID
);

template <typename ExportType>
ExportType GetKernelExport(
	PCWSTR ExportName
);

PKLDR_DATA_TABLE_ENTRY GetKldrDataByName(
	PCWSTR ModuleName
);

template <typename T>
bool GetAddress(
	UINT64 Base,
	UINT64 Size,
	PCUCHAR Pattern,
	PCSTR WildCard,
	INT OpcodeBytes,
	INT AddressBytes,
	T& Found
);

typedef uintptr_t(__fastcall* _MiFillPteHierarchy)(
	PVOID VirtualAddress,
	PPTE_HIERARCHY PteHierarchy
);

PLIST_ENTRY PsLoadedModuleList = nullptr;
PERESOURCE PsLoadedModuleResource = nullptr;
_MiFillPteHierarchy MiFillPteHierarchy = nullptr;

PKLDR_DATA_TABLE_ENTRY GetKldrDataByName(PCWSTR ModuleName)
{
	PKLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;

	UNICODE_STRING ModName = { 0 };

	RtlInitUnicodeString(&ModName, ModuleName);

	if (PsLoadedModuleList == nullptr || PsLoadedModuleResource == nullptr)
	{
		return nullptr;
	}

	KeEnterCriticalRegion();

	ExAcquireResourceSharedLite(PsLoadedModuleResource, true);

	auto CurrentKldrEntry = (PKLDR_DATA_TABLE_ENTRY)(PsLoadedModuleList->Flink);

	while ((PLIST_ENTRY)(CurrentKldrEntry) != PsLoadedModuleList)
	{
		if (RtlEqualUnicodeString(&CurrentKldrEntry->BaseDllName, &ModName, true))
		{
			LdrEntry = CurrentKldrEntry;
			break;
		}

		CurrentKldrEntry = (PKLDR_DATA_TABLE_ENTRY)(CurrentKldrEntry->InLoadOrderLinks.Flink);
	}

	ExReleaseResourceLite(PsLoadedModuleResource);

	KeLeaveCriticalRegion();

	return LdrEntry;
}


template <typename T>
bool GetAddress(UINT64 Base, UINT64 Size, PCUCHAR Pattern, PCSTR WildCard, INT OpcodeBytes, INT AddressBytes, T& Found)
{
	auto CheckMask = [&](PCUCHAR Data, PCUCHAR Pattern, PCSTR WildCard)
	{
		for (; *WildCard; ++WildCard, ++Data, ++Pattern)
		{
			if (*WildCard == 'x' && *Data != *Pattern)
			{
				return false;
			}
		}

		return *WildCard == 0;
	};

	auto Resolve = [&](PVOID InstructionAddress, INT OpcodeBytes, INT AddressBytes)
	{
		ULONG64 InstructionAddr = (ULONG64)InstructionAddress;

		AddressBytes += OpcodeBytes;

		ULONG32 RelativeOffset = *(ULONG32*)(InstructionAddr + OpcodeBytes);

		Found = (T)(InstructionAddr + RelativeOffset + AddressBytes);
	};


	for (auto i = 0; i < Size; i++)
	{
		if (CheckMask((PUCHAR)(Base + i), Pattern, WildCard))
		{
			PVOID InstrAddress = (PVOID)(Base + i);

			Resolve(InstrAddress, OpcodeBytes, AddressBytes);

			return true;
		}
	}

	return false;
}

template <typename ExportType>
ExportType GetKernelExport(PCWSTR ExportName)
{
	UNICODE_STRING ExpName = { 0 };

	RtlInitUnicodeString(&ExpName, ExportName);

	ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&ExpName);

	return ExportAddress ? ExportAddress : ExportType(nullptr);
}

VOID LocateData(VOID)
{
	UCHAR MiFillPteHierarchyPattern[] = "\xE8\x00\x00\x00\x00\x48\x8B\x74\xDC\x00";

	PsLoadedModuleList = GetKernelExport<PLIST_ENTRY>(L"PsLoadedModuleList");

	PsLoadedModuleResource = GetKernelExport<PERESOURCE>(L"PsLoadedModuleResource");

	auto Ntos = GetKldrDataByName(L"ntoskrnl.exe");

	GetAddress((UINT64)Ntos->DllBase, Ntos->SizeOfImage, MiFillPteHierarchyPattern, "x????xxxx?", 1, 4, MiFillPteHierarchy) ?
		DbgPrint("[+] Found MiFillPteHierarchy: %p\n", MiFillPteHierarchy) : DbgPrint("[+] Failed to locate MiFillPteHierarchy\n");
}

ULONG64 GetPhysicalAddress(PVOID VirtualAddress)
{
	PTE_HIERARCHY PteHierarchy = { 0 };

	VIRTUAL_ADDRESS VirtualAddrr = { reinterpret_cast<ULONG64>(VirtualAddress) };

	MiFillPteHierarchy(VirtualAddress, &PteHierarchy);

	if (!PteHierarchy.Pte || !PteHierarchy.Pde || !PteHierarchy.Pdpte || !PteHierarchy.Pml4e)
	{
		return 0;
	}

	if (PteHierarchy.Pdpte->PageSize)
	{
		return (PteHierarchy.Pdpte->PageFrameNumber << PAGE_SHIFT) + VirtualAddrr.Offset1Gb;
	}

	else if (PteHierarchy.Pde->PageSize)
	{
		return (PteHierarchy.Pde->PageFrameNumber << PAGE_SHIFT) + VirtualAddrr.Offset2mb;
	}

	else
	{
		return (PteHierarchy.Pte->PageFrameNumber << PAGE_SHIFT) + VirtualAddrr.Offset4Kb;
	}
}


/*
@ Not Used But Can Be Helpful !

	NTSTATUS WritePhysicalMemory(
		ULONG64 TargetAddress,
		PVOID Buffer,
		SIZE_T Size,
		SIZE_T& BytesWritten
	);

	template <typename T>
	auto ReadVirtualMemory(
		HANDLE Pid,
		ULONG64 Address,
		SIZE_T& BytesReaden
	) -> T;

	NTSTATUS WriteVirtualMemory(
		HANDLE Pid,
		ULONG64 Address,
		PVOID Buffer,
		SIZE_T Size,
		SIZE_T& BytesWritten
	);

*/

PAGE_TABLE_INFO QueryPageTableInfo(
	PVOID Address,
	HANDLE Pid
);

ULONG64 GetUserDirOffset(VOID)
{
	RTL_OSVERSIONINFOW VersionInfo = { 0 };

	RtlGetVersion(&VersionInfo);

	switch (VersionInfo.dwBuildNumber)
	{
		case WINDOWS_1803:
			return 0x0278;
			break;
		case WINDOWS_1809:
			return 0x0278;
			break;
		case WINDOWS_1903:
			return 0x0280;
			break;
		case WINDOWS_1909:
			return 0x0280;
			break;
		case WINDOWS_2004:
			return 0x0388;
			break;
		case WINDOWS_20H2:
			return 0x0388;
			break;
		case WINDOWS_21H1:
			return 0x0388;
			break;
		default:
			return 0x0388;
	}
}

PVOID GetProcessCr3(HANDLE Pid)
{
	PEPROCESS Process = nullptr; 

	if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &Process)))
	{
		return 0;
	}

	PVOID ProcessDirBase = reinterpret_cast<PVOID>(
		ReadKernelMemory<PTE>((ULONG64)Process + 0x28).PageFrameNumber << 12
	);
	
	if (ProcessDirBase == 0)
	{		
		PVOID ProcessUserDirBase = reinterpret_cast<PVOID>(
			ReadKernelMemory<PTE>((ULONG64)Process + GetUserDirOffset()).PageFrameNumber << 12
		);

		return ProcessUserDirBase;
	}
	
	return ProcessDirBase;
}

VOID QueryPagingInfo(VOID)
{
	CR0 Cr0        =	{ 0 };
	CR4 Cr4        =	{ 0 };
	IA32_EFER Efer =        { 0 };

	Cr0.Value = __readcr0();

	Cr4.Value = __readcr4();

	Efer.Value = __readmsr(IA32_EFER_MSR);

	if (Cr0.PagingEnable)
	{
		DbgPrint("[+] Paging Is Enabled\n");
		
		if (!Cr4.PhysicalAddressExtension)
		{
			DbgPrint("[+] System is using 32-bit paging mode\n");
		}

		else if (Efer.Ia32eModeActive)
		{
			DbgPrint("[+] System is using 4 level paging mode\n");
		}

		else
		{
			DbgPrint("[+] System is using 32-bit PAE Paging mode\n");
		}
	}
	
	else
	{
		DbgPrint("[+] Paging is not enabled on ur system ? do u live in a cave !\n");
	}
}

template <typename T>
auto ReadPhysicalMemory(T* TargetAddress) -> T
{
	T Buffer = { 0 };

	SIZE_T BytesReaden = 0;

	MM_COPY_ADDRESS Address = { 0 };
	
	Address.PhysicalAddress.QuadPart = reinterpret_cast<LONGLONG>(TargetAddress);
	
	if (!NT_SUCCESS(MmCopyMemory(&Buffer, Address, sizeof(T), MM_COPY_MEMORY_PHYSICAL, &BytesReaden)))
	{
		return T();
	}

	return Buffer;
}

template <typename T>
auto GetVirtualAddress(ULONG64 PhysicalAddress) -> T
{
	PHYSICAL_ADDRESS PhysicalAddr = { PhysicalAddress };
		
	return reinterpret_cast<T>(MmGetVirtualForPhysical(PhysicalAddr));
}

template <typename T>
auto ReadKernelMemory(ULONG64 Address) -> T
{
	T Buffer = { 0 };

	if (memcpy((PVOID)&Buffer, (PVOID)Address, sizeof(T)) == nullptr)
	{
		return T();
	}

	return Buffer;
}

/*	
  @ Not used but maybe useful 

	 NTSTATUS WritePhysicalMemory(ULONG64 TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T& BytesWritten)
	{
		if (TargetAddress == 0)
		{
			return STATUS_UNSUCCESSFUL;
		}

		PHYSICAL_ADDRESS PhysicalAddress = { TargetAddress };

		PVOID Mapped = MmMapIoSpaceEx(PhysicalAddress, Size, PAGE_READWRITE);

		if (Mapped == nullptr)
		{
			return STATUS_UNSUCCESSFUL;
		}

		RtlCopyMemory(Mapped, Buffer, Size);

		BytesWritten = Size; 

		MmUnmapIoSpace(Mapped, Size);

		return STATUS_SUCCESS;
	}

	template <typename T>
	auto ReadVirtualMemory(HANDLE Pid, ULONG64 Address, SIZE_T& BytesReaden) -> T
	{
		T Buffer = { 0 };
	
		ULONG64 PhysicalAddress = GetPhysicalAddress(Address, Pid);
	
		return ReadPhysicalMemory<T>(PhysicalAddress, &Buffer, sizeof(T), BytesReaden)
	}


NTSTATUS WriteVirtualMemory(HANDLE Pid, ULONG64 Address, PVOID Buffer, SIZE_T Size, SIZE_T& BytesWritten)
{
	ULONG64 PhysicalAddress = GetPhysicalAddress(Address, Pid);

	return WritePhysicalMemory(PhysicalAddress, &Buffer, Size, BytesWritten);
}
*/

PAGE_TABLE_INFO QueryPageTableInfo(PVOID Address, HANDLE Pid)
{
	SIZE_T BytesReaden = 0;
	PAGE_TABLE_INFO PageTableInfo = { 0 };
	VIRTUAL_ADDRESS VirtualAddress = { reinterpret_cast<ULONG64>(Address) };
	PVOID DirBase = GetProcessCr3(Pid);

	const auto Pml4ePhysc = reinterpret_cast<PPML4E>((ULONG64)DirBase) + VirtualAddress.Pml4Index;

	PageTableInfo.Pml4e = GetVirtualAddress<PPML4E>((ULONG64)Pml4ePhysc);

	const auto Pml4e = ReadPhysicalMemory<PML4E>(Pml4ePhysc);

	if (Pml4e.Value == NULL || Pml4e.Present == NULL)
	{
		return PAGE_TABLE_INFO{};
	}

	const auto PdptePhysc = reinterpret_cast<PPDPTE>((ULONG64)Pml4e.PageFrameNumber << PAGE_SHIFT) + VirtualAddress.PdptIndex;

	PageTableInfo.Pdpte = GetVirtualAddress<PPDPTE>((ULONG64)PdptePhysc);

	const auto Pdpte = ReadPhysicalMemory<PDPTE>(PdptePhysc);

	if (Pdpte.Value == NULL || Pdpte.Present == NULL)
	{
		return PAGE_TABLE_INFO{};
	}

	const auto PdePhysc = reinterpret_cast<PPDE>((ULONG64)Pdpte.PageFrameNumber << PAGE_SHIFT) + VirtualAddress.PdIndex;

	PageTableInfo.Pde = GetVirtualAddress<PPDE>((ULONG64)PdePhysc);

	const auto Pde = ReadPhysicalMemory<PDE>(PdePhysc);

	if (Pde.Value == NULL || Pde.Present == NULL)
	{
		return PAGE_TABLE_INFO{};
	}

	if (Pdpte.PageSize)
	{
		PageTableInfo.PageSize = _1gbPage;
	}

	else if (Pde.PageSize)
	{
		PageTableInfo.PageSize = _2mbPage;
	}

	else
	{
		PageTableInfo.PageSize = _4kbPage;
	}

	const auto PtePhysc = reinterpret_cast<PPTE>((ULONG64)Pde.PageFrameNumber << PAGE_SHIFT) + VirtualAddress.PtIndex;

	PageTableInfo.Pte = GetVirtualAddress<PPTE>((ULONG64)PtePhysc);

	return PageTableInfo;
}

ULONG64 GetPhysicalAddress(ULONG64 VirtualAddress, HANDLE Pid)
{
	SIZE_T BytesReaden = 0;
	VIRTUAL_ADDRESS VirtualAddr = { VirtualAddress };
	PVOID DirBase = GetProcessCr3(Pid);

	const auto Pml4ePhysc = reinterpret_cast<PPML4E>((ULONG64)DirBase) + VirtualAddr.Pml4Index;

	const auto Pml4e = ReadPhysicalMemory<PML4E>(Pml4ePhysc);

	if (Pml4e.Value == NULL || Pml4e.Present == NULL)
	{
		return 0;
	}

	const auto PdptePhysc = reinterpret_cast<PPDPTE>((ULONG64)Pml4e.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.PdptIndex;

	const auto Pdpte = ReadPhysicalMemory<PDPTE>(PdptePhysc);

	if (Pdpte.Value == NULL || Pdpte.Present == NULL)
	{
		return 0;
	}

	// handle 1gb pages 

	if (Pdpte.PageSize)
	{
		return (Pdpte.PageFrameNumber << 12) + VirtualAddr.Offset1Gb;
	}

	const auto PdePhysc = reinterpret_cast<PPDE>((ULONG64)Pdpte.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.PdIndex;

	const auto Pde = ReadPhysicalMemory<PDE>(PdePhysc);

	if (Pde.Value == NULL || Pde.Present == NULL)
	{
		return 0;
	}

	// handle 2mb pages 

	if (Pde.PageSize)
	{
		return (Pde.PageFrameNumber << 12) + VirtualAddr.Offset2mb;
	}

	const auto PtePhysc = reinterpret_cast<PPTE>((ULONG64)Pde.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.PtIndex;

	const auto Pte = ReadPhysicalMemory<PTE>(PtePhysc);
	
	if (Pte.Value == NULL || Pte.Present == NULL)
	{
		return 0;
	}

	return (Pte.PageFrameNumber << 12) + VirtualAddr.Offset4Kb;
}

EXTERN_C PPEB PsGetProcessPeb(PEPROCESS Process);

// idea: https://www.unknowncheats.me/forum/3073682-post6.html

PVOID GetModuleBase(PEPROCESS Process, PCWSTR ModuleName)
{
	PVOID ModuleBase = nullptr;
	UNICODE_STRING ModName = { 0 };
	HANDLE ProcessId = PsGetProcessId(Process);
	PPEB Peb = PsGetProcessPeb(Process);
	PVOID DirBase = GetProcessCr3(ProcessId);
	ULONG64 OldCr3 = __readcr3();
	KIRQL Irql = 0;

	if (Process == nullptr)
	{
		return nullptr; 
	}

	RtlInitUnicodeString(&ModName, ModuleName);
	Irql = KeRaiseIrqlToDpcLevel();
	__writecr3((ULONG64)DirBase);

	PPEB_LDR_DATA Ldr = Peb->Ldr;

	if (Ldr == nullptr)
	{
		__writecr3(OldCr3);
		KeLowerIrql(Irql);
		return nullptr;
	}

	PLIST_ENTRY Head = Ldr->InMemoryOrderModuleList.Flink;
	PLIST_ENTRY CurrentLdr = Head;

	do
	{
		PLDR_DATA_TABLE_ENTRY CurrentLdrEntry = CONTAINING_RECORD(CurrentLdr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (RtlEqualUnicodeString(&CurrentLdrEntry->BaseDllName, &ModName, true))
		{
			ModuleBase = CurrentLdrEntry->DllBase;
			break;
		}

		CurrentLdr = CurrentLdrEntry->InMemoryOrderLinks.Flink;

	} while (Head != CurrentLdr);

	__writecr3(OldCr3);
	KeLowerIrql(Irql);
	return ModuleBase; 
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	DbgPrint("[+] DriverObject: %p [+]\n", DriverObject);

	LocateData();

	QueryPagingInfo();

	PAGE_TABLE_INFO PageTableInfo = QueryPageTableInfo(DriverObject, (HANDLE)4);

	DbgPrint("[+] Queyring Page Table Info For DriverObject (%p)\n", DriverObject);
	DbgPrint("[+] ======================================================== [+]\n");
	DbgPrint("[+] Found PML4E: %p\n", PageTableInfo.Pml4e);
	DbgPrint("[+] Found PDPTE: %p\n", PageTableInfo.Pdpte);
	DbgPrint("[+] Found PDE : %p\n", PageTableInfo.Pde);
	DbgPrint("[+] Found PTE : %p\n", PageTableInfo.Pte);

	switch (PageTableInfo.PageSize)
	{
		case _4kbPage:
		{
			DbgPrint("[+] VA is mapped to a 4kb page\n");
			break;
		}

		case _2mbPage:
		{
			DbgPrint("[+] VA is mapped to a 2mb page\n");
			break;
		}

		case _1gbPage:
		{
			DbgPrint("[+] VA is mapped to a 1gb page\n");
			break;
		}
	default:
		break;
	}

	DbgPrint("[+] DriverObject Physical: %x\n", MmGetPhysicalAddress(DriverObject));
	DbgPrint("[+] DriverObject Physical: %x\n", GetPhysicalAddress((ULONG64)DriverObject, (HANDLE)4));
	DbgPrint("[+] DriverObject Physical: %x\n", GetPhysicalAddress(DriverObject));

	PEPROCESS Process = nullptr; 

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)3712, &Process)))
	{
		DbgPrint("[+] Failed to lookup process\n");
	}

	else
	{
		UNICODE_STRING ModuleName = { 0 };
		PVOID modbase = GetModuleBase(Process, L"ntdll.dll");
		DbgPrint("[+] ntdll.dll modbase: %p\n", modbase);
	}

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("[+] %wZ Unloaded\n", DriverObject->DriverName);
}
