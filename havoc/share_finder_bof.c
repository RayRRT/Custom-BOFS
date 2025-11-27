#include <windows.h>
#include <lm.h>

DECLSPEC_IMPORT VOID WINAPI BeaconPrintf(int type, char* fmt, ...);

DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetShareEnum(LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);

DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpiW(LPCWSTR, LPCWSTR);

BOOL IsInteresting(WCHAR* filename) {
    int len = KERNEL32$lstrlenW(filename);
    if (len < 4) return FALSE;
    
    WCHAR* ext = filename + len - 4;
    
    if (KERNEL32$lstrcmpiW(ext, L".txt") == 0) return TRUE;
    if (KERNEL32$lstrcmpiW(ext, L".ps1") == 0) return TRUE;
    if (KERNEL32$lstrcmpiW(ext, L".xml") == 0) return TRUE;
    if (KERNEL32$lstrcmpiW(ext, L".bat") == 0) return TRUE;
    if (KERNEL32$lstrcmpiW(ext, L".cmd") == 0) return TRUE;
    if (KERNEL32$lstrcmpiW(ext, L".vbs") == 0) return TRUE;
    if (KERNEL32$lstrcmpiW(ext, L".log") == 0) return TRUE;
    if (KERNEL32$lstrcmpiW(ext, L".ini") == 0) return TRUE;
    
    return FALSE;
}

void ListFiles(WCHAR* sharePath) {
    WCHAR searchPath[512];
    KERNEL32$lstrcpyW(searchPath, sharePath);
    KERNEL32$lstrcatW(searchPath, L"\\*");
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind = KERNEL32$FindFirstFileW(searchPath, &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(0, "[-] Cannot access: %ls\n", sharePath);
        return;
    }
    
    int count = 0;
    do {
        if (findData.cFileName[0] == L'.') continue;
        
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (IsInteresting(findData.cFileName)) {
                BeaconPrintf(0, "  %ls\n", findData.cFileName);
                count++;
                if (count >= 20) break;
            }
        }
    } while (KERNEL32$FindNextFileW(hFind, &findData) && count < 20);
    
    KERNEL32$FindClose(hFind);
}

void go(char* args, int len) {
    WCHAR dcName[256] = {0};
    
    BeaconPrintf(0, "[+] Share Enumeration\n\n");
    
    if (KERNEL32$GetEnvironmentVariableW(L"LOGONSERVER", dcName, 256) == 0) {
        BeaconPrintf(0, "[-] No domain controller\n");
        return;
    }
    
    WCHAR* dc = dcName;
    if (dc[0] == L'\\' && dc[1] == L'\\') dc += 2;
    
    BeaconPrintf(0, "[+] DC: %ls\n\n", dc);
    
    // Enumerar shares
    LPBYTE buffer = NULL;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    
    BeaconPrintf(0, "=== Shares ===\n");
    
    if (NETAPI32$NetShareEnum(dc, 1, &buffer, MAX_PREFERRED_LENGTH, 
        &entriesRead, &totalEntries, NULL) == NERR_Success) {
        
        SHARE_INFO_1* shareInfo = (SHARE_INFO_1*)buffer;
        
        for (DWORD i = 0; i < entriesRead; i++) {
            WCHAR* name = shareInfo[i].shi1_netname;
            int len = KERNEL32$lstrlenW(name);
            
            // Solo shares no administrativos
            if (len > 0 && name[len - 1] != L'$') {
                BeaconPrintf(0, "\\\\%ls\\%ls", dc, name);
                if (shareInfo[i].shi1_remark && shareInfo[i].shi1_remark[0]) {
                    BeaconPrintf(0, " - %ls", shareInfo[i].shi1_remark);
                }
                BeaconPrintf(0, "\n");
            }
        }
        
        NETAPI32$NetApiBufferFree(buffer);
    } else {
        BeaconPrintf(0, "[-] Failed to enumerate\n");
    }
    
    // NETLOGON
    BeaconPrintf(0, "\n=== NETLOGON Files ===\n");
    WCHAR netlogon[256];
    KERNEL32$lstrcpyW(netlogon, L"\\\\");
    KERNEL32$lstrcatW(netlogon, dc);
    KERNEL32$lstrcatW(netlogon, L"\\NETLOGON");
    ListFiles(netlogon);
    
    BeaconPrintf(0, "\n[+] Complete\n");
}
