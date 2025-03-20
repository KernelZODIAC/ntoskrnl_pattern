#include <ntddk.h>

#define WIN_7          7601
#define WIN_8          9200
#define WIN_8_1        9600
#define WIN_10_1507    10240
#define WIN_10_1511    10586
#define WIN_10_1607    14393
#define WIN_10_1703    15063
#define WIN_10_1709    16299
#define WIN_10_1803    17134
#define WIN_10_1809    17763
#define WIN_10_1903    18362
#define WIN_10_1909    18363
#define WIN_10_2004    19041
#define WIN_10_20H2    19042
#define WIN_10_21H1    19043
#define WIN_10_21H2    19044
#define WIN_10_22H2    19045
#define WIN_11_INITIAL 22000
#define WIN_11_22H2    22621
#define WIN_11_23H2    22631
#define WIN_11_24H2    26100

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeparation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformationObsolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPatchInformation,
    SystemVerifierFaultsInformation,
    SystemSystemPartitionInformation,
    SystemSystemDiskInformation,
    SystemProcessorPerformanceDistribution,
    SystemNumaProximityNodeInformation,
    SystemDynamicTimeZoneInformation,
    SystemCodeIntegrityInformation,
    SystemProcessorMicrocodeUpdateInformation,
    SystemProcessorBrandString,
    SystemVirtualAddressInformation,
    SystemLogicalProcessorAndGroupInformation,
    SystemProcessorCycleTimeInformation,
    SystemStoreInformation,
    SystemRegistryAppendString,
    SystemAitSamplingValue,
    SystemVhdBootInformation,
    SystemCpuQuotaInformation,
    SystemNativeBasicInformation,
    SystemErrorPortTimeouts,
    SystemLowPriorityIoInformation,
    SystemTpmBootEntropyInformation,
    SystemVerifierCountersInformation,
    SystemPagedPoolInformationEx,
    SystemSystemPtesInformationEx,
    SystemNodeDistanceInformation,
    SystemAcpiAuditInformation,
    SystemBasicPerformanceInformation,
    SystemQueryPerformanceCounterInformation,
    SystemSessionBigPoolInformation,
    SystemBootGraphicsInformation,
    SystemScrubPhysicalMemoryInformation,
    SystemBadPageInformation,
    SystemProcessorProfileControlArea,
    SystemCombinePhysicalMemoryInformation,
    SystemEntropyInterruptTimingInformation,
    SystemConsoleInformation,
    SystemPlatformBinaryInformation,
    SystemPolicyInformation,
    SystemHypervisorProcessorCountInformation,
    SystemDeviceDataInformation,
    SystemDeviceDataEnumerationInformation,
    SystemMemoryTopologyInformation,
    SystemMemoryChannelInformation,
    SystemBootLogoInformation,
    SystemProcessorPerformanceInformationEx,
    SystemCriticalProcessErrorLogInformation,
    SystemSecureBootPolicyInformation,
    SystemPageFileInformationEx,
    SystemSecureBootInformation,
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation,
    SystemFullProcessInformation,
    SystemKernelDebuggerInformationEx,
    SystemBootMetadataInformation,
    SystemSoftRebootInformation,
    SystemElamCertificateInformation,
    SystemOfflineDumpConfigInformation,
    SystemProcessorFeaturesInformation,
    SystemRegistryReconciliationInformation,
    SystemEdidInformation,
    SystemManufacturingInformation,
    SystemEnergyEstimationConfigInformation,
    SystemHypervisorDetailInformation,
    SystemProcessorCycleStatsInformation,
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation,
    SystemKernelDebuggerFlags,
    SystemCodeIntegrityPolicyInformation,
    SystemIsolatedUserModeInformation,
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation,
    SystemAllowedCpuSetsInformation,
    SystemVsmProtectionInformation,
    SystemInterruptCpuSetsInformation,
    SystemSecureBootPolicyFullInformation,
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation,
    SystemRootSiloInformation,
    SystemCpuSetInformation,
    SystemCpuSetTagInformation,
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation,
    SystemCodeIntegrityPlatformManifestInformation,
    SystemInterruptSteeringInformation,
    SystemSupportedProcessorArchitectures,
    SystemMemoryUsageInformation,
    SystemCodeIntegrityCertificateInformation,
    SystemPhysicalMemoryInformation,
    SystemControlFlowTransition,
    SystemKernelDebuggingAllowed,
    SystemActivityModerationExeState,
    SystemActivityModerationUserSettings,
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegritySyntheticCacheInformation,
    SystemFeatureConfigurationInformation,
    SystemFeatureConfigurationSectionInformation,
    SystemFeatureUsageSubscriptionInformation,
    SystemSecureSpeculationControlInformation,
    SystemSpacesBootInformation,
    SystemFwRamdiskInformation,
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation,
    SystemDifClearRuleClassInformation,
    SystemDifApplyPluginVerificationOnDriver,
    SystemDifRemovePluginVerificationOnDriver,
    SystemShadowStackInformation,
    SystemBuildVersionInformation,
    SystemPoolLimitInformation,
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation,
    SystemDpcWatchdogInformation,
    SystemDpcWatchdogInformation2,
    SystemSupportedProcessorArchitectures2,
    SystemSingleProcessorRelationshipInformation,
    SystemXfgCheckFailureInformation,
    SystemIommuStateInformation,
    SystemHypervisorMinrootInformation,
    SystemHypervisorBootPagesInformation,
    SystemPointerAuthInformation,
    SystemSecureKernelDebuggerInformation,
    SystemOriginalImageFeatureInformation,
    SystemMemoryNumaInformation,
    SystemMemoryNumaPerformanceInformation,
    SystemCodeIntegritySignedPoliciesFullInformation,
    SystemSecureCoreInformation,
    SystemTrustedAppsRuntimeInformation,
    SystemBadPageInformationEx,
    SystemResourceDeadlockTimeout,
    SystemBreakOnContextUnwindFailureInformation,
    SystemOslRamdiskInformation,
    SystemCodeIntegrityPolicyManagementInformation,
    SystemMemoryNumaCacheInformation,
    SystemProcessorFeaturesBitMapInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

static ULONG HexCharToByte(CHAR c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

static NTSTATUS ParsePattern(IN PCSTR pattern, OUT PUCHAR* outBytes, OUT PCHAR* outMask, OUT ULONG* outCount) {
    SIZE_T len = strlen(pattern);
    ULONG maxTokens = (ULONG)len;
    PUCHAR bytes = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, maxTokens, 'pPtn');
    if (!bytes) return STATUS_INSUFFICIENT_RESOURCES;
    PCHAR mask = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, maxTokens + 1, 'pPtn');
    if (!mask) { ExFreePoolWithTag(bytes, 'pPtn'); return STATUS_INSUFFICIENT_RESOURCES; }
    ULONG count = 0;
    for (SIZE_T i = 0; i < len;) {
        if (pattern[i] == ' ') { i++; continue; }
        if (pattern[i] == '?') {
            bytes[count] = 0;
            mask[count] = '?';
            i += ((i + 1) < len && pattern[i + 1] == '?') ? 2 : 1;
            count++;
        }
        else {
            if ((i + 1) >= len) break;
            bytes[count] = (UCHAR)((HexCharToByte(pattern[i]) << 4) | HexCharToByte(pattern[i + 1]));
            mask[count] = 'x';
            count++;
            i += 2;
        }
    }
    mask[count] = '\0';
    *outBytes = bytes; *outMask = mask; *outCount = count;
    return STATUS_SUCCESS;
}

NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);

static NTSTATUS GetKernelModuleInfo(OUT PVOID* outBase, OUT PULONG outSize) {
    NTSTATUS status;
    ULONG bytes = 0;
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
    if (!bytes) return STATUS_UNSUCCESSFUL;
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bytes, 'kMdl');
    if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;
    status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bytes, &bytes);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(buffer, 'kMdl'); return status; }
    typedef struct _SYSTEM_MODULE_ENTRY {
        PVOID Reserved[2];
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
    } SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;
    typedef struct _SYSTEM_MODULE_INFORMATION {
        ULONG Count;
        SYSTEM_MODULE_ENTRY Module[1];
    } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
    if (pModuleInfo->Count == 0) { ExFreePoolWithTag(buffer, 'kMdl'); return STATUS_UNSUCCESSFUL; }
    *outBase = pModuleInfo->Module[0].Base;
    *outSize = pModuleInfo->Module[0].Size;
    ExFreePoolWithTag(buffer, 'kMdl');
    return STATUS_SUCCESS;
}

PVOID FindKernelPattern(IN PCSTR pattern) {
    PUCHAR patternBytes = NULL;
    PCHAR mask = NULL;
    ULONG patternCount = 0;
    NTSTATUS status = ParsePattern(pattern, &patternBytes, &mask, &patternCount);
    if (!NT_SUCCESS(status) || patternCount == 0) {
        if (patternBytes) ExFreePoolWithTag(patternBytes, 'pPtn');
        if (mask) ExFreePoolWithTag(mask, 'pPtn');
        return NULL;
    }
    PVOID kernelBase = NULL;
    ULONG kernelSize = 0;
    status = GetKernelModuleInfo(&kernelBase, &kernelSize);
    if (!NT_SUCCESS(status) || !kernelBase || kernelSize == 0) {
        ExFreePoolWithTag(patternBytes, 'pPtn');
        ExFreePoolWithTag(mask, 'pPtn');
        return NULL;
    }
    PUCHAR start = (PUCHAR)kernelBase;
    PUCHAR end = start + kernelSize - patternCount;
    for (PUCHAR current = start; current < end; current++) {
        BOOLEAN found = TRUE;
        for (ULONG i = 0; i < patternCount; i++) {
            if (mask[i] == 'x' && current[i] != patternBytes[i]) { found = FALSE; break; }
        }
        if (found) {
            ExFreePoolWithTag(patternBytes, 'pPtn');
            ExFreePoolWithTag(mask, 'pPtn');
            return (PVOID)current;
        }
    }
    ExFreePoolWithTag(patternBytes, 'pPtn');
    ExFreePoolWithTag(mask, 'pPtn');
    return NULL;
}
