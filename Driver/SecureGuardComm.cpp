/*
 * SecureGuard Driver Communication Library
 * 
 * User-mode DLL for communicating with the SecureGuard kernel driver.
 * Provides interface for the C# application to interact with kernel-level protection.
 * 
 * Copyright (c) 2024 SecureGuard Inc.
 * All Rights Reserved.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winioctl.h>

// ============================================================================
// DEFINITIONS
// ============================================================================

#define SG_DEVICE_NAME             "\\\\.\\SecureGuardDriver"
#define SG_DLL_NAME                "SecureGuardComm.dll"

#define SG_IOCTL_GET_VERSION             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_START_PROTECTION        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_STOP_PROTECTION         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_ADD_PROTECTED_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_REMOVE_PROTECTED_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_ADD_PROTECTED_FILE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_REMOVE_PROTECTED_FILE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_ADD_BLOCKED_FILE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_GET_EVENTS              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SG_IOCTL_SET_CONFIG              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Event Types
#define SG_EVENT_PROCESS_CREATE          1
#define SG_EVENT_PROCESS_TERMINATE        2
#define SG_EVENT_FILE_CREATE             3
#define SG_EVENT_FILE_WRITE              4
#define SG_EVENT_FILE_DELETE             5
#define SG_EVENT_REGISTRY_CREATE         6
#define SG_EVENT_REGISTRY_DELETE         7
#define SG_EVENT_REGISTRY_MODIFY         8
#define SG_EVENT_NETWORK_CONNECT         9
#define SG_EVENT_DLL_LOAD                10

// ============================================================================
// DATA STRUCTURES
// ============================================================================

typedef struct _SG_CONFIG {
    ULONG EnableProcessProtection;
    ULONG EnableFileProtection;
    ULONG EnableRegistryProtection;
    ULONG EnableNetworkProtection;
    ULONG EnableDllMonitoring;
    ULONG LogLevel;
    ULONG MaxLogEntries;
} SG_CONFIG, *PSG_CONFIG;

typedef struct _SG_EVENT {
    ULONG EventType;
    ULONG ProcessId;
    ULONG ThreadId;
    WCHAR FilePath[MAX_PATH];
    WCHAR ProcessName[256];
    WCHAR AdditionalData[512];
    ULONG64 Timestamp;
    ULONG Action;
} SG_EVENT, *PSG_EVENT;

typedef struct _SG_PROTECTED_PROCESS {
    ULONG ProcessId;
    WCHAR ProcessName[256];
} SG_PROTECTED_PROCESS, *PSG_PROTECTED_PROCESS;

// ============================================================================
// EXPORTED FUNCTIONS
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Driver connection management
__declspec(dllexport) HANDLE WINAPI SGConnectToDriver();
__declspec(dllexport) BOOL WINAPI SGDisconnectFromDriver(HANDLE hDevice);

// Protection control
__declspec(dllexport) BOOL WINAPI SGStartProtection(HANDLE hDevice);
__declspec(dllexport) BOOL WINAPI SGStopProtection(HANDLE hDevice);

// Process protection
__declspec(dllexport) BOOL WINAPI SGAddProtectedProcess(HANDLE hDevice, ULONG processId);
__declspec(dllexport) BOOL WINAPI SGRemoveProtectedProcess(HANDLE hDevice, ULONG processId);

// File protection
__declspec(dllexport) BOOL WINAPI SGAddProtectedFile(HANDLE hDevice, LPCWSTR filePath);
__declspec(dllexport) BOOL WINAPI SGRemoveProtectedFile(HANDLE hDevice, LPCWSTR filePath);
__declspec(dllexport) BOOL WINAPI SGBlockFile(HANDLE hDevice, LPCWSTR filePath);

// Registry protection
__declspec(dllexport) BOOL WINAPI SGAddProtectedRegistryKey(HANDLE hDevice, LPCWSTR keyPath);
__declspec(dllexport) BOOL WINAPI SGRemoveProtectedRegistryKey(HANDLE hDevice, LPCWSTR keyPath);

// Configuration
__declspec(dllexport) BOOL WINAPI SGSetConfig(HANDLE hDevice, PSG_CONFIG config);
__declspec(dllexport) BOOL WINAPI SGGetConfig(HANDLE hDevice, PSG_CONFIG config);

// Event retrieval
__declspec(dllexport) BOOL WINAPI SGGetEvents(HANDLE hDevice, PSG_EVENT events, ULONG* count);

// Version info
__declspec(dllexport) ULONG WINAPI SGGetDriverVersion(HANDLE hDevice);

// Status
__declspec(dllexport) BOOL WINAPI SGIsDriverRunning();

#ifdef __cplusplus
}
#endif

// ============================================================================
// IMPLEMENTATION
// ============================================================================

HANDLE WINAPI SGConnectToDriver()
{
    HANDLE hDevice;
    
    hDevice = CreateFile(
        SG_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND) {
            printf("[SecureGuardComm] Failed to connect to driver: %lu\n", error);
        }
        return NULL;
    }
    
    printf("[SecureGuardComm] Connected to driver successfully\n");
    return hDevice;
}

BOOL WINAPI SGDisconnectFromDriver(HANDLE hDevice)
{
    if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        printf("[SecureGuardComm] Disconnected from driver\n");
        return TRUE;
    }
    return FALSE;
}

BOOL WINAPI SGStartProtection(HANDLE hDevice)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    
    if (!hDevice) return FALSE;
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_START_PROTECTION,
        NULL,
        0,
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    if (success && result) {
        printf("[SecureGuardComm] Protection started\n");
    } else {
        printf("[SecureGuardComm] Failed to start protection\n");
    }
    
    return success && result;
}

BOOL WINAPI SGStopProtection(HANDLE hDevice)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    
    if (!hDevice) return FALSE;
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_STOP_PROTECTION,
        NULL,
        0,
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    if (success && result) {
        printf("[SecureGuardComm] Protection stopped\n");
    }
    
    return success && result;
}

BOOL WINAPI SGAddProtectedProcess(HANDLE hDevice, ULONG processId)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    
    if (!hDevice) return FALSE;
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_ADD_PROTECTED_PROCESS,
        &processId,
        sizeof(processId),
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    if (success && result) {
        printf("[SecureGuardComm] Added protected process: %lu\n", processId);
    }
    
    return success && result;
}

BOOL WINAPI SGRemoveProtectedProcess(HANDLE hDevice, ULONG processId)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    
    if (!hDevice) return FALSE;
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_REMOVE_PROTECTED_PROCESS,
        &processId,
        sizeof(processId),
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    return success && result;
}

BOOL WINAPI SGAddProtectedFile(HANDLE hDevice, LPCWSTR filePath)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    WCHAR pathBuffer[MAX_PATH];
    
    if (!hDevice || !filePath) return FALSE;
    
    wcscpy_s(pathBuffer, MAX_PATH, filePath);
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_ADD_PROTECTED_FILE,
        pathBuffer,
        sizeof(pathBuffer),
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    if (success && result) {
        printf("[SecureGuardComm] Added protected file: %ws\n", filePath);
    }
    
    return success && result;
}

BOOL WINAPI SGRemoveProtectedFile(HANDLE hDevice, LPCWSTR filePath)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    WCHAR pathBuffer[MAX_PATH];
    
    if (!hDevice || !filePath) return FALSE;
    
    wcscpy_s(pathBuffer, MAX_PATH, filePath);
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_REMOVE_PROTECTED_FILE,
        pathBuffer,
        sizeof(pathBuffer),
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    return success && result;
}

BOOL WINAPI SGBlockFile(HANDLE hDevice, LPCWSTR filePath)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    WCHAR pathBuffer[MAX_PATH];
    
    if (!hDevice || !filePath) return FALSE;
    
    wcscpy_s(pathBuffer, MAX_PATH, filePath);
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_ADD_BLOCKED_FILE,
        pathBuffer,
        sizeof(pathBuffer),
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    if (success && result) {
        printf("[SecureGuardComm] Blocked file: %ws\n", filePath);
    }
    
    return success && result;
}

BOOL WINAPI SGAddProtectedRegistryKey(HANDLE hDevice, LPCWSTR keyPath)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    WCHAR pathBuffer[MAX_PATH];
    
    if (!hDevice || !keyPath) return FALSE;
    
    wcscpy_s(pathBuffer, MAX_PATH, keyPath);
    
    // Uses same IOCTL as file protection (repurposed)
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_ADD_PROTECTED_FILE,  // Repurposed for registry
        pathBuffer,
        sizeof(pathBuffer),
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    return success && result;
}

BOOL WINAPI SGRemoveProtectedRegistryKey(HANDLE hDevice, LPCWSTR keyPath)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    WCHAR pathBuffer[MAX_PATH];
    
    if (!hDevice || !keyPath) return FALSE;
    
    wcscpy_s(pathBuffer, MAX_PATH, keyPath);
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_REMOVE_PROTECTED_FILE,  // Repurposed for registry
        pathBuffer,
        sizeof(pathBuffer),
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    return success && result;
}

BOOL WINAPI SGSetConfig(HANDLE hDevice, PSG_CONFIG config)
{
    DWORD bytesReturned = 0;
    ULONG result = 0;
    BOOL success;
    
    if (!hDevice || !config) return FALSE;
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_SET_CONFIG,
        config,
        sizeof(SG_CONFIG),
        &result,
        sizeof(result),
        &bytesReturned,
        NULL
    );
    
    if (success && result) {
        printf("[SecureGuardComm] Configuration updated\n");
    }
    
    return success && result;
}

BOOL WINAPI SGGetConfig(HANDLE hDevice, PSG_CONFIG config)
{
    DWORD bytesReturned = 0;
    BOOL success;
    
    if (!hDevice || !config) return FALSE;
    
    // Not implemented in driver yet - would require additional IOCTL
    memset(config, 0, sizeof(SG_CONFIG));
    
    return FALSE;
}

BOOL WINAPI SGGetEvents(HANDLE hDevice, PSG_EVENT events, ULONG* count)
{
    DWORD bytesReturned = 0;
    BOOL success;
    
    if (!hDevice || !events || !count) return FALSE;
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_GET_EVENTS,
        NULL,
        0,
        events,
        sizeof(SG_EVENT) * (*count),
        &bytesReturned,
        NULL
    );
    
    if (success) {
        *count = bytesReturned / sizeof(SG_EVENT);
    }
    
    return success;
}

ULONG WINAPI SGGetDriverVersion(HANDLE hDevice)
{
    DWORD bytesReturned = 0;
    ULONG version = 0;
    BOOL success;
    
    if (!hDevice) return 0;
    
    success = DeviceIoControl(
        hDevice,
        SG_IOCTL_GET_VERSION,
        NULL,
        0,
        &version,
        sizeof(version),
        &bytesReturned,
        NULL
    );
    
    if (success) {
        return version;
    }
    
    return 0;
}

BOOL WINAPI SGIsDriverRunning()
{
    HANDLE hDevice;
    BOOL isRunning = FALSE;
    
    hDevice = CreateFile(
        SG_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hDevice != INVALID_HANDLE_VALUE) {
        isRunning = TRUE;
        CloseHandle(hDevice);
    }
    
    return isRunning;
}

// ============================================================================
// DLL ENTRY POINT
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            printf("[SecureGuardComm] DLL loaded\n");
            break;
            
        case DLL_PROCESS_DETACH:
            printf("[SecureGuardComm] DLL unloaded\n");
            break;
    }
    
    return TRUE;
}

