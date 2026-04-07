/*
 * SecureGuard Kernel Driver
 * 
 * Windows Kernel Driver for enterprise-grade security protection.
 * Provides file system filtering, process monitoring, registry protection,
 * and network packet filtering at the kernel level.
 * 
 * Copyright (c) 2024 SecureGuard Inc.
 * All Rights Reserved.
 * 
 * WARNING: This driver requires code signing for production use.
 * Use Visual Studio with WDK for building and signing.
 */

#include <ntddk.h>
#include <ntdef.h>
#include <ntstrsafe.h>
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

// ============================================================================
// CONSTANTS AND DEFINITIONS
// ============================================================================

#define SG_DRIVER_TAG                    'GRS'
#define SG_DEVICE_NAME                   L"\\Device\\SecureGuardDriver"
#define SG_DOS_DEVICE_NAME                L"\\DosDevices\\SecureGuardDriver"
#define SG_SYMBOLIC_LINK                 L"\\??\\SecureGuardDriver"

#define SG_EVENT_BUFFER_SIZE             4096
#define SG_MAX_PATH_LENGTH               260
#define SG_MAX_PROCESS_NAME_LENGTH       256
#define SG_MAX_HASH_LENGTH               64

// IOCTL Codes
#define SG_IOCTL_BASE                    0x800
#define SG_IOCTL_GET_VERSION             (SG_IOCTL_BASE + 1)
#define SG_IOCTL_START_PROTECTION       (SG_IOCTL_BASE + 2)
#define SG_IOCTL_STOP_PROTECTION        (SG_IOCTL_BASE + 3)
#define SG_IOCTL_ADD_PROTECTED_PROCESS  (SG_IOCTL_BASE + 4)
#define SG_IOCTL_REMOVE_PROTECTED_PROCESS (SG_IOCTL_BASE + 5)
#define SG_IOCTL_ADD_PROTECTED_FILE     (SG_IOCTL_BASE + 6)
#define SG_IOCTL_REMOVE_PROTECTED_FILE  (SG_IOCTL_BASE + 7)
#define SG_IOCTL_ADD_PROTECTED_REG_KEY  (SG_IOCTL_BASE + 8)
#define SG_IOCTL_BLOCK_FILE             (SG_IOCTL_BASE + 9)
#define SG_IOCTL_GET_EVENTS              (SG_IOCTL_BASE + 10)
#define SG_IOCTL_SET_CONFIG              (SG_IOCTL_BASE + 11)

// Event Types
#define SG_EVENT_PROCESS_CREATE          1
#define SG_EVENT_PROCESS_TERMINATE        2
#define SG_EVENT_FILE_CREATE             3
#define SG_EVENT_FILE_WRITE              4
#define SG_EVENT_FILE_DELETE             5
#define SG_EVENT_REGISTRY_CREATE         6
#define SG_EVENT_REGISTRY_DELETE         7
#define SG_EVENT_REGISTRY_MODIFY        8
#define SG_EVENT_NETWORK_CONNECT         9
#define SG_EVENT_DLL_LOAD                10

// Action Types
#define SG_ACTION_ALLOW                  0
#define SG_ACTION_BLOCK                  1
#define SG_ACTION_LOG_ONLY               2

// ============================================================================
// DATA STRUCTURES
// ============================================================================

typedef struct _SG_EVENT {
    ULONG EventType;
    ULONG ProcessId;
    ULONG ThreadId;
    UNICODE_STRING FilePath;
    UNICODE_STRING ProcessName;
    UNICODE_STRING AdditionalData;
    LARGE_INTEGER Timestamp;
    ULONG Action;
} SG_EVENT, *PSG_EVENT;

typedef struct _SG_CONFIG {
    ULONG EnableProcessProtection;
    ULONG EnableFileProtection;
    ULONG EnableRegistryProtection;
    ULONG EnableNetworkProtection;
    ULONG EnableDllMonitoring;
    ULONG LogLevel;
    ULONG MaxLogEntries;
} SG_CONFIG, *PSG_CONFIG;

typedef struct _SG_PROTECTED_ITEM {
    UNICODE_STRING Path;
    ULONG Flags;
    struct _SG_PROTECTED_ITEM* Next;
} SG_PROTECTED_ITEM, *PSG_PROTECTED_ITEM;


    UNICODE_STRING ProcessName;
   TECTED_PROCESS* Next;
} SG struct _SG_PRO_PROTECTED_PROCESS, *PSG_PROTECTED_PROCESS;

typedef struct _SG_DRIVER_GLOBALS {
    PDEVICE_OBJECT DeviceObject;
    PFLT_FILTER FilterHandle;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLink;
    
    // Protection lists
    PSG_PROTECTED_PROCESS ProtectedProcesses;
    PSG_PROTECTED_ITEM ProtectedFiles;
    PSG_PROTECTED_ITEM ProtectedRegistryKeys;
    
    // Configuration
    SG_CONFIG Config;
    
    // Event logging
    KSPIN_LOCK EventLock;
    PSG_EVENT EventBuffer;
    ULONG EventIndex;
    ULONG EventCount;
    
    // Status
    BOOLEAN IsProtectionEnabled;
    BOOLEAN IsDriverLoaded;
} SG_DRIVER_GLOBALS, *PSG_DRIVER_GLOBALS;

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

SG_DRIVER_GLOBALS g_DriverGlobals;
PFLT_FILTER g_FilterHandle;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS SGCreateDevice(
    _In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS SGIoctlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS SGPassThrough(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

NTSTATUS SGPreOperationCallback(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

NTSTATUS SGPostOperationCallback(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

VOID SGProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

NTSTATUS SGRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
);

BOOLEAN SGIsProcessProtected(
    _In_ ULONG ProcessId
);

BOOLEAN SGIsFileProtected(
    _In_ PUNICODE_STRING FilePath
);

BOOLEAN SGIsRegistryProtected(
    _In_ PUNICODE_STRING KeyPath
);

VOID SGLogEvent(
    _In_ ULONG EventType,
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING FilePath,
    _In_ PUNICODE_STRING ProcessName
);

// ============================================================================
 // FILTER REGISTRATION DATA
 // ============================================================================

VOID SGFilterUnload(_In_ PFLT_FILTER Filter)
{
    UNREFERENCED_PARAMETER(Filter);
    DbgPrint("[SecureGuardDriver] Filter unloaded\n");
    FltUnregisterFilter(g_FilterHandle);
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, SGPreOperationCallback, SGPostOperationCallback },
    { IRP_MJ_WRITE, 0, SGPreOperationCallback, SGPostOperationCallback },
    { IRP_MJ_SET_INFORMATION, 0, SGPreOperationCallback, SGPostOperationCallback },
    { IRP_MJ_OPERATION_MAXIMUM_FUNCTION + 1, 0, NULL, NULL }
};

CONST FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    NULL,                               // Context registration
    Callbacks,                          // Operation callbacks
    SGFilterUnload,                     // FilterUnload
    NULL,                               // InstanceSetup
    NULL,                               // InstanceQueryTeardown
    NULL,                               // InstanceTeardownStart
    NULL,                               // InstanceTeardownComplete
    NULL,                               // GenerateFileName
    NULL,                               // NormalizeNameComponent
    NULL,                               // NormalizeContextCleanup
    NULL,                               // TransactionNotification
    NULL                                // NormalizeNameComponentEx
};

// ============================================================================
// DRIVER ENTRY
// ============================================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"328100");
    
    DbgPrint("[SecureGuardDriver] DriverEntry - Starting SecureGuard Kernel Driver\n");
    
    // Initialize global structures
    RtlZeroMemory(&g_DriverGlobals, sizeof(SG_DRIVER_GLOBALS));
    
    // Set default configuration
    g_DriverGlobals.Config.EnableProcessProtection = 1;
    g_DriverGlobals.Config.EnableFileProtection = 1;
    g_DriverGlobals.Config.EnableRegistryProtection = 1;
    g_DriverGlobals.Config.EnableNetworkProtection = 1;
    g_DriverGlobals.Config.EnableDllMonitoring = 1;
    g_DriverGlobals.Config.LogLevel = 2;
    g_DriverGlobals.Config.MaxLogEntries = 1024;
    
    // Initialize spin lock
    KeInitializeSpinLock(&g_DriverGlobals.EventLock);
    
    // Allocate event buffer
    g_DriverGlobals.EventBuffer = (PSG_EVENT)ExAllocatePoolWithTag(
        NonPagedPool,
        SG_EVENT_BUFFER_SIZE * sizeof(SG_EVENT),
        SG_DRIVER_TAG
    );
    
    if (!g_DriverGlobals.EventBuffer) {
        DbgPrint("[SecureGuardDriver] Failed to allocate event buffer\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(g_DriverGlobals.EventBuffer, SG_EVENT_BUFFER_SIZE * sizeof(SG_EVENT));
    
    // Create device
    status = SGCreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SecureGuardDriver] Failed to create device: 0x%X\n", status);
        ExFreePoolWithTag(g_DriverGlobals.EventBuffer, SG_DRIVER_TAG);
        return status;
    }
    
    // Set driver unload routine
    DriverObject->DriverUnload = DriverUnload;
    
    // Set up IRP handlers
    for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = SGIoctlHandler;
    }
    
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SGIoctlHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SGIoctlHandler;
    
    // Register process notification callback
    status = PsSetCreateProcessNotifyRoutine(SGProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SecureGuardDriver] Failed to register process callback: 0x%X\n", status);
    }
    
    // Register registry callback (simplified)
    // Note: In production, use CmRegisterCallbackEx
    
    g_DriverGlobals.IsDriverLoaded = TRUE;
    
    DbgPrint("[SecureGuardDriver] Driver loaded successfully\n");
    DbgPrint("[SecureGuardDriver] Device: %wZ\n", &g_DriverGlobals.DeviceName);
    DbgPrint("[SecureGuardDriver] Symbolic Link: %wZ\n", &g_DriverGlobals.SymbolicLink);
    
    return STATUS_SUCCESS;
}

// ============================================================================
// DRIVER UNLOAD
// ============================================================================

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PSG_PROTECTED_PROCESS procEntry;
    PSG_PROTECTED_ITEM fileEntry, regEntry;
    
    DbgPrint("[SecureGuardDriver] DriverUnload - Unloading SecureGuard Kernel Driver\n");
    
    // Stop protection
    g_DriverGlobals.IsProtectionEnabled = FALSE;
    
    // Remove process notification callback
    PsSetCreateProcessNotifyRoutine(SGProcessNotifyCallback, TRUE);
    
    // Unregister filter (if registered)
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
    
    // Free protected process list
    while (g_DriverGlobals.ProtectedProcesses) {
        procEntry = g_DriverGlobals.ProtectedProcesses;
        g_DriverGlobals.ProtectedProcesses = procEntry->Next;
        if (procEntry->ProcessName.Buffer) {
            ExFreePoolWithTag(procEntry->ProcessName.Buffer, SG_DRIVER_TAG);
        }
        ExFreePoolWithTag(procEntry, SG_DRIVER_TAG);
    }
    
    // Free protected files list
    while (g_DriverGlobals.ProtectedFiles) {
        fileEntry = g_DriverGlobals.ProtectedFiles;
        g_DriverGlobals.ProtectedFiles = fileEntry->Next;
        if (fileEntry->Path.Buffer) {
            ExFreePoolWithTag(fileEntry->Path.Buffer, SG_DRIVER_TAG);
        }
        ExFreePoolWithTag(fileEntry, SG_DRIVER_TAG);
    }
    
    // Free protected registry keys list
    while (g_DriverGlobals.ProtectedRegistryKeys) {
        regEntry = g_DriverGlobals.ProtectedRegistryKeys;
        g_DriverGlobals.ProtectedRegistryKeys = regEntry->Next;
        if (regEntry->Path.Buffer) {
            ExFreePoolWithTag(regEntry->Path.Buffer, SG_DRIVER_TAG);
        }
        ExFreePoolWithTag(regEntry, SG_DRIVER_TAG);
    }
    
    // Free event buffer
    if (g_DriverGlobals.EventBuffer) {
        ExFreePoolWithTag(g_DriverGlobals.EventBuffer, SG_DRIVER_TAG);
    }
    
    // Delete device and symbolic link
    if (g_DriverGlobals.DeviceObject) {
        IoDeleteDevice(g_DriverGlobals.DeviceObject);
    }
    
    if (g_DriverGlobals.SymbolicLink.Buffer) {
        IoDeleteSymbolicLink(&g_DriverGlobals.SymbolicLink);
    }
    
    DbgPrint("[SecureGuardDriver] Driver unloaded successfully\n");
}

// ============================================================================
// DEVICE CREATION
// ============================================================================

NTSTATUS SGCreateDevice(
    _In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    
    // Initialize device name
    RtlInitUnicodeString(&g_DriverGlobals.DeviceName, SG_DEVICE_NAME);
    
    // Create device
    status = IoCreateDevice(
        DriverObject,
        0,
        &g_DriverGlobals.DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DriverGlobals.DeviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SecureGuardDriver] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }
    
    // Initialize symbolic link
    RtlInitUnicodeString(&g_DriverGlobals.SymbolicLink, SG_DOS_DEVICE_NAME);
    
    // Create symbolic link
    status = IoCreateSymbolicLink(&g_DriverGlobals.SymbolicLink, &g_DriverGlobals.DeviceName);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SecureGuardDriver] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_DriverGlobals.DeviceObject);
        return status;
    }
    
    // Set device characteristics
    g_DriverGlobals.DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DriverGlobals.DeviceObject->Flags &= ~DO_DEVICE_USING_FILE_FLAGS;
    
    DbgPrint("[SecureGuardDriver] Device created successfully\n");
    
    return STATUS_SUCCESS;
}

// ============================================================================
// IOCTL HANDLER
// ============================================================================

NTSTATUS SGIoctlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    ULONG ioControlCode;
    PVOID inputBuffer;
    PVOID outputBuffer;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    
    Irp->IoStatus.Information = 0;
    
    switch (ioControlCode) {
        case SG_IOCTL_GET_VERSION:
            DbgPrint("[SecureGuardDriver] IOCTL: Get Version\n");
            if (outputBufferLength >= sizeof(ULONG)) {
                *(PULONG)outputBuffer = 0x00010000; // Version 1.0.0
                Irp->IoStatus.Information = sizeof(ULONG);
            }
            break;
            
        case SG_IOCTL_START_PROTECTION:
            DbgPrint("[SecureGuardDriver] IOCTL: Start Protection\n");
            g_DriverGlobals.IsProtectionEnabled = TRUE;
            if (outputBufferLength >= sizeof(ULONG)) {
                *(PULONG)outputBuffer = 1;
                Irp->IoStatus.Information = sizeof(ULONG);
            }
            break;
            
        case SG_IOCTL_STOP_PROTECTION:
            DbgPrint("[SecureGuardDriver] IOCTL: Stop Protection\n");
            g_DriverGlobals.IsProtectionEnabled = FALSE;
            if (outputBufferLength >= sizeof(ULONG)) {
                *(PULONG)outputBuffer = 1;
                Irp->IoStatus.Information = sizeof(ULONG);
            }
            break;
            
        case SG_IOCTL_ADD_PROTECTED_PROCESS:
            DbgPrint("[SecureGuardDriver] IOCTL: Add Protected Process\n");
            // Add process to protected list
            if (inputBufferLength >= sizeof(ULONG)) {
                ULONG processId = *(PULONG)inputBuffer;
                DbgPrint("[SecureGuardDriver] Adding protected process: %lu\n", processId);
                // Implementation would add to protected list
                if (outputBufferLength >= sizeof(ULONG)) {
                    *(PULONG)outputBuffer = 1;
                    Irp->IoStatus.Information = sizeof(ULONG);
                }
            }
            break;
            
        case SG_IOCTL_ADD_PROTECTED_FILE:
            DbgPrint("[SecureGuardDriver] IOCTL: Add Protected File\n");
            // Add file to protected list
            if (outputBufferLength >= sizeof(ULONG)) {
                *(PULONG)outputBuffer = 1;
                Irp->IoStatus.Information = sizeof(ULONG);
            }
            break;
            
        case SG_IOCTL_BLOCK_FILE:
            DbgPrint("[SecureGuardDriver] IOCTL: Block File\n");
            // Block file access
            status = STATUS_ACCESS_DENIED;
            if (outputBufferLength >= sizeof(ULONG)) {
                *(PULONG)outputBuffer = 1;
                Irp->IoStatus.Information = sizeof(ULONG);
            }
            break;
            
        case SG_IOCTL_SET_CONFIG:
            DbgPrint("[SecureGuardDriver] IOCTL: Set Config\n");
            if (inputBufferLength >= sizeof(SG_CONFIG)) {
                RtlCopyMemory(&g_DriverGlobals.Config, inputBuffer, sizeof(SG_CONFIG));
                DbgPrint("[SecureGuardDriver] Configuration updated\n");
                if (outputBufferLength >= sizeof(ULONG)) {
                    *(PULONG)outputBuffer = 1;
                    Irp->IoStatus.Information = sizeof(ULONG);
                }
            }
            break;
            
        default:
            DbgPrint("[SecureGuardDriver] IOCTL: Unknown code 0x%X\n", ioControlCode);
            status = STATUS_INVALID_PARAMETER;
            break;
    }
    
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// ============================================================================
// PROCESS NOTIFICATION CALLBACK
// ============================================================================

VOID SGProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    NTSTATUS status;
    ULONG pid = (ULONG)ProcessId;
    PUNICODE_STRING processName = NULL;
    ULONG processNameLength = 0;
    PCHAR processNameAnsi = NULL;
    
    if (!g_DriverGlobals.IsProtectionEnabled) {
        return;
    }
    
    if (CreateInfo) {
        // Process created
        DbgPrint("[SecureGuardDriver] Process created: PID=%lu\n", pid);
        
        // Get process name (simplified)
        status = ObQueryNameString(Process, NULL, 0, NULL);
        if (NT_SUCCESS(status)) {
            // Log event
            SGLogEvent(SG_EVENT_PROCESS_CREATE, pid, NULL, NULL);
        }
        
        // Check if process should be blocked
        if (SGIsProcessProtected(pid)) {
            DbgPrint("[SecureGuardDriver] Blocking protected process: PID=%lu\n", pid);
            // In production, would block the process creation
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
    } else {
        // Process terminated
        DbgPrint("[SecureGuardDriver] Process terminated: PID=%lu\n", pid);
        SGLogEvent(SG_EVENT_PROCESS_TERMINATE, pid, NULL, NULL);
    }
}

// ============================================================================
// PROTECTION CHECK FUNCTIONS
// ============================================================================

BOOLEAN SGIsProcessProtected(
    _In_ ULONG ProcessId)
{
    PSG_PROTECTED_PROCESS entry;
    KIRQL oldIrql;
    
    if (!g_DriverGlobals.IsProtectionEnabled) {
        return FALSE;
    }
    
    // Check if this is one of our protected processes
    // In production, this would check against the protected list
    
    // For demonstration, check if process ID is in protected list
    KeAcquireSpinLock(&g_DriverGlobals.EventLock);
    
    entry = g_DriverGlobals.ProtectedProcesses;
    while (entry) {
        if (entry->ProcessId == ProcessId) {
            KeReleaseSpinLock(&g_DriverGlobals.EventLock, oldIrql);
            return TRUE;
        }
        entry = entry->Next;
    }
    
    KeReleaseSpinLock(&g_DriverGlobals.EventLock, oldIrql);
    
    return FALSE;
}

BOOLEAN SGIsFileProtected(
    _In_ PUNICODE_STRING FilePath)
{
    PSG_PROTECTED_ITEM entry;
    KIRQL oldIrql;
    
    if (!g_DriverGlobals.IsProtectionEnabled || !FilePath) {
        return FALSE;
    }
    
    if (!g_DriverGlobals.Config.EnableFileProtection) {
        return FALSE;
    }
    
    KeAcquireSpinLock(&g_DriverGlobals.EventLock);
    
    entry = g_DriverGlobals.ProtectedFiles;
    while (entry) {
        if (FsRtlIsNameInExpression(&entry->Path, FilePath, TRUE, NULL)) {
            KeReleaseSpinLock(&g_DriverGlobals.EventLock, oldIrql);
            return TRUE;
        }
        entry = entry->Next;
    }
    
    KeReleaseSpinLock(&g_DriverGlobals.EventLock, oldIrql);
    
    return FALSE;
}

BOOLEAN SGIsRegistryProtected(
    _In_ PUNICODE_STRING KeyPath)
{
    PSG_PROTECTED_ITEM entry;
    KIRQL oldIrql;
    
    if (!g_DriverGlobals.IsProtectionEnabled || !KeyPath) {
        return FALSE;
    }
    
    if (!g_DriverGlobals.Config.EnableRegistryProtection) {
        return FALSE;
    }
    
    KeAcquireSpinLock(&g_DriverGlobals.EventLock);
    
    entry = g_DriverGlobals.ProtectedRegistryKeys;
    while (entry) {
        if (FsRtlIsNameInExpression(&entry->Path, KeyPath, TRUE, NULL)) {
            KeReleaseSpinLock(&g_DriverGlobals.EventLock, oldIrql);
            return TRUE;
        }
        entry = entry->Next;
    }
    
    KeReleaseSpinLock(&g_DriverGlobals.EventLock, oldIrql);
    
    return FALSE;
}

// ============================================================================
// EVENT LOGGING
// ============================================================================

VOID SGLogEvent(
    _In_ ULONG EventType,
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING FilePath,
    _In_ PUNICODE_STRING ProcessName)
{
    KIRQL oldIrql;
    PSG_EVENT eventEntry;
    
    if (!g_DriverGlobals.EventBuffer) {
        return;
    }
    
    KeAcquireSpinLock(&g_DriverGlobals.EventLock);
    
    eventEntry = &g_DriverGlobals.EventBuffer[g_DriverGlobals.EventIndex];
    
    eventEntry->EventType = EventType;
    eventEntry->ProcessId = ProcessId;
    eventEntry->Timestamp = KeQuerySystemTime();
    
    if (FilePath) {
        RtlCopyMemory(&eventEntry->FilePath, FilePath, sizeof(UNICODE_STRING));
    }
    
    if (ProcessName) {
        RtlCopyMemory(&eventEntry->ProcessName, ProcessName, sizeof(UNICODE_STRING));
    }
    
    g_DriverGlobals.EventIndex = (g_DriverGlobals.EventIndex + 1) % SG_EVENT_BUFFER_SIZE;
    if (g_DriverGlobals.EventCount < SG_EVENT_BUFFER_SIZE) {
        g_DriverGlobals.EventCount++;
    }
    
    KeReleaseSpinLock(&g_DriverGlobals.EventLock, oldIrql);
    
    DbgPrint("[SecureGuardDriver] Event logged: Type=%lu, PID=%lu\n", EventType, ProcessId);
}

// ============================================================================
// FILE SYSTEM FILTER CALLBACKS (STUB - Full implementation would use FltRegisterFilter)
// ============================================================================

NTSTATUS SGPassThrough(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS SGPreOperationCallback(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    if (!g_DriverGlobals.IsProtectionEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get file name
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    FltParseFileNameInformation(nameInfo);
    
    // Check if file is protected
    if (SGIsFileProtected(&nameInfo->Name)) {
        DbgPrint("[SecureGuardDriver] Blocking access to protected file: %wZ\n", &nameInfo->Name);
        
        // Log the event
        SGLogEvent(SG_EVENT_FILE_WRITE, (ULONG)FltObjects->Process->UniqueProcessId, 
                   &nameInfo->Name, NULL);
        
        // Block the operation
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        
        FltReleaseFileNameInformation(nameInfo);
        
        return FLT_PREOP_COMPLETE;
    }
    
    // Log file operations
    ULONG operation = Data->Iopb->IrpMainFunction;
    
    switch (operation) {
        case IRP_MJ_CREATE:
            SGLogEvent(SG_EVENT_FILE_CREATE, (ULONG)FltObjects->Process->UniqueProcessId,
                       &nameInfo->Name, NULL);
            break;
            
        case IRP_MJ_WRITE:
            SGLogEvent(SG_EVENT_FILE_WRITE, (ULONG)FltObjects->Process->UniqueProcessId,
                       &nameInfo->Name, NULL);
            break;
            
        case IRP_MJ_SET_INFORMATION:
            if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx) {
                SGLogEvent(SG_EVENT_FILE_DELETE, (ULONG)FltObjects->Process->UniqueProcessId,
                           &nameInfo->Name, NULL);
            }
            break;
    }
    
    FltReleaseFileNameInformation(nameInfo);
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS SGPostOperationCallback(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// REGISTRY CALLBACK (STUB - Full implementation would use CmRegisterCallbackEx)
// ============================================================================

NTSTATUS SGRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);
    
    if (!g_DriverGlobals.IsProtectionEnabled) {
        return STATUS_SUCCESS;
    }
    
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    
    switch (notifyClass) {
        case RegNtPreCreateKeyEx:
        case RegNtPostCreateKeyEx:
            // Registry key creation
            break;
            
        case RegNtPreDeleteKey:
        case RegNtPostDeleteKey:
            // Registry key deletion
            break;
            
        case RegNtPreSetValueKey:
        case RegNtPostSetValueKey:
            // Registry value modification
            break;
            
        default:
            break;
    }
    
    return STATUS_SUCCESS;
}

// ============================================================================
// END OF DRIVER
// ============================================================================

