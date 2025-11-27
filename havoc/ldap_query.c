#include <windows.h>
#include <winldap.h>

DECLSPEC_IMPORT VOID WINAPI BeaconPrintf(int type, char* fmt, ...);

DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_initW(PWCHAR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, void*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWCHAR, PWCHAR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sW(LDAP*, PWCHAR, ULONG, PWCHAR, PWCHAR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWCHAR* WINAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWCHAR);
DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenW(LDAP*, LDAPMessage*, PWCHAR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_freeW(PWCHAR*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR*);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

void BuildDomainDN(WCHAR* domain, WCHAR* output) {
    int i, j = 0;
    BOOL first = TRUE;
    WCHAR component[128];
    
    output[0] = L'\0';
    
    for (i = 0; i <= KERNEL32$lstrlenW(domain); i++) {
        if (domain[i] == L'.' || domain[i] == L'\0') {
            component[j] = L'\0';
            if (j > 0) {
                if (!first) KERNEL32$lstrcatW(output, L",");
                KERNEL32$lstrcatW(output, L"DC=");
                KERNEL32$lstrcatW(output, component);
                first = FALSE;
            }
            j = 0;
        } else {
            component[j++] = domain[i];
        }
    }
}

void go(char* args, int len) {
    LDAP* ld = NULL;
    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    ULONG version = LDAP_VERSION3;
    PWCHAR attrs[] = {L"cn", L"servicePrincipalName", L"objectSid", L"c", L"mail", NULL};
    WCHAR domainDN[256] = {0};
    WCHAR userDomain[128] = {0};
    
    BeaconPrintf(0, "[+] Starting LDAP queries\n");
    
    if (KERNEL32$GetEnvironmentVariableW(L"USERDNSDOMAIN", userDomain, 128) == 0) {
        BeaconPrintf(0, "[-] Could not get USERDNSDOMAIN\n");
        return;
    }
    
    BuildDomainDN(userDomain, domainDN);
    BeaconPrintf(0, "[+] Domain: %ls | Base DN: %ls\n", userDomain, domainDN);
    
    ld = WLDAP32$ldap_initW(NULL, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(0, "[-] Failed to initialize LDAP\n");
        return;
    }
    
    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    
    if (WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        BeaconPrintf(0, "[-] LDAP bind failed\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    BeaconPrintf(0, "[+] Connected to LDAP\n\n=== Users with SPN set ===\n");
    
    // Query 1: Users with SPN
    PWCHAR filter1 = L"(&(objectClass=user)(|(servicePrincipalName=MSSQLSvc*)(servicePrincipalName=HTTP*)(servicePrincipalName=CIFS*)))";
    
    if (WLDAP32$ldap_search_sW(ld, domainDN, LDAP_SCOPE_SUBTREE, filter1, attrs, 0, &searchResult) == LDAP_SUCCESS) {
        int count = 0;
        for (entry = WLDAP32$ldap_first_entry(ld, searchResult); entry; entry = WLDAP32$ldap_next_entry(ld, entry)) {
            PWCHAR* cn = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
            PWCHAR* spn = WLDAP32$ldap_get_valuesW(ld, entry, L"servicePrincipalName");
            
            if (cn && spn) {
                BeaconPrintf(0, "User: %ls | SPN: %ls\n", cn[0], spn[0]);
                count++;
            }
            
            if (cn) WLDAP32$ldap_value_freeW(cn);
            if (spn) WLDAP32$ldap_value_freeW(spn);
        }
        BeaconPrintf(0, "[+] Total: %d users\n", count);
        WLDAP32$ldap_msgfree(searchResult);
    } else {
        BeaconPrintf(0, "[-] SPN query failed\n");
    }
    
    // Query 2: Australian employees
    BeaconPrintf(0, "\n=== Employees from Australia ===\n");
    PWCHAR filter2 = L"(&(objectClass=user)(c=AU))";
    
    if (WLDAP32$ldap_search_sW(ld, domainDN, LDAP_SCOPE_SUBTREE, filter2, attrs, 0, &searchResult) == LDAP_SUCCESS) {
        int count = 0;
        for (entry = WLDAP32$ldap_first_entry(ld, searchResult); entry; entry = WLDAP32$ldap_next_entry(ld, entry)) {
            PWCHAR* cn = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
            PWCHAR* mail = WLDAP32$ldap_get_valuesW(ld, entry, L"mail");
            struct berval** sidBerval = WLDAP32$ldap_get_values_lenW(ld, entry, L"objectSid");
            
            if (cn) {
                BeaconPrintf(0, "User: %ls", cn[0]);
                
                if (mail) {
                    BeaconPrintf(0, " | Email: %ls", mail[0]);
                }
                
                // Convertir SID usando API de Windows
                if (sidBerval && sidBerval[0]) {
                    LPWSTR sidString = NULL;
                    if (ADVAPI32$ConvertSidToStringSidW((PSID)sidBerval[0]->bv_val, &sidString)) {
                        BeaconPrintf(0, " | SID: %ls", sidString);
                        KERNEL32$LocalFree(sidString);
                    }
                }
                
                BeaconPrintf(0, "\n");
                count++;
            }
            
            if (cn) WLDAP32$ldap_value_freeW(cn);
            if (mail) WLDAP32$ldap_value_freeW(mail);
            if (sidBerval) WLDAP32$ldap_value_free_len(sidBerval);
        }
        BeaconPrintf(0, "[+] Total: %d employees\n", count);
        WLDAP32$ldap_msgfree(searchResult);
    } else {
        BeaconPrintf(0, "[-] Australia query failed\n");
    }
    
    WLDAP32$ldap_unbind(ld);
    BeaconPrintf(0, "[+] Queries completed\n");
}
