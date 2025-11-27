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
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_freeW(PWCHAR*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT PWCHAR WINAPI WLDAP32$ldap_get_dnW(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ldap_memfreeW(PWCHAR);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);

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
    PWCHAR attrs[] = {L"cn", L"distinguishedName", NULL};
    WCHAR domainDN[256] = {0};
    WCHAR userDomain[128] = {0};
    WCHAR configDN[512] = {0};
    
    if (KERNEL32$GetEnvironmentVariableW(L"USERDNSDOMAIN", userDomain, 128) == 0) {
        BeaconPrintf(0, "[-] Could not get domain\n");
        return;
    }
    
    BuildDomainDN(userDomain, domainDN);
    KERNEL32$lstrcatW(configDN, L"CN=Configuration,");
    KERNEL32$lstrcatW(configDN, domainDN);
    
    ld = WLDAP32$ldap_initW(NULL, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(0, "[-] LDAP init failed\n");
        return;
    }
    
    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    
    if (WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        BeaconPrintf(0, "[-] LDAP bind failed\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }
    
    PWCHAR filter = L"(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))";
    
    BeaconPrintf(0, "[+] ESC1 Vulnerable Certificate Templates\n[+] Domain: %ls\n\n", userDomain);
    
    if (WLDAP32$ldap_search_sW(ld, configDN, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &searchResult) == LDAP_SUCCESS) {
        int count = 0;
        
        for (entry = WLDAP32$ldap_first_entry(ld, searchResult); entry; entry = WLDAP32$ldap_next_entry(ld, entry)) {
            PWCHAR* cn = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
            PWCHAR dn = WLDAP32$ldap_get_dnW(ld, entry);
            
            if (cn) {
                count++;
                BeaconPrintf(0, "[%d] %ls\n", count, cn[0]);
                if (dn) {
                    BeaconPrintf(0, "    DN: %ls\n", dn);
                }
                BeaconPrintf(0, "    [!] ESC1: ENROLLEE_SUPPLIES_SUBJECT enabled\n\n");
            }
            
            if (cn) WLDAP32$ldap_value_freeW(cn);
            if (dn) WLDAP32$ldap_memfreeW(dn);
        }
        
        if (count > 0) {
            BeaconPrintf(0, "[+] Found %d vulnerable templates\n", count);
        } else {
            BeaconPrintf(0, "[+] No vulnerable templates found\n");
        }
        
        WLDAP32$ldap_msgfree(searchResult);
    } else {
        BeaconPrintf(0, "[-] Query failed - check permissions\n");
    }
    
    WLDAP32$ldap_unbind(ld);
}
