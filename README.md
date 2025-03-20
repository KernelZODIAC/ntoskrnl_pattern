example usage:
```
#include <ntddk.h>
#include "PatternScanner.h"
#include "patterns_kernel.h"


VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("DriverUnload: Driver unloaded.\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    PVOID pNtCreateThreadEx = FindKernelPattern(NtCreateThreadEx_Pattern());
    if (pNtCreateThreadEx)
    {
        DbgPrint("DriverEntry: Function NtCreateThreadEx founded at address: 0x%p\n", pNtCreateThreadEx);
    }
    else
    {
        DbgPrint("DriverEntry: Function NtCreateThreadEx not found!\n");
    }
    
    DriverObject->DriverUnload = DriverUnload;
    return STATUS_UNSUCCESSFUL;
}
```
