# Havoc BOF Collection

Collection of Beacon Object Files (BOFs) for Active Directory enumeration and reconnaissance in controlled lab environments. Tested on Havoc C2, may also work on Cobalt Strike.

## Tools

| BOF | Description |
|-----|-------------|
| `whoami_bof` | Retrieves current user context, SID, hostname, local admin status, and token elevation |
| `ldap_query` | Queries LDAP for users with SPNs (Kerberoastable) and employees by country |
| `share_finder_bof` | Enumerates network shares on the domain controller and lists interesting files in NETLOGON |
| `esc1_finder_bof` | Finds AD CS certificate templates vulnerable to ESC1 (ENROLLEE_SUPPLIES_SUBJECT) |

## Compilation

Compile using MinGW:

```bash
x86_64-w64-mingw32-gcc -c whoami_bof.c -o whoami_bof.o
x86_64-w64-mingw32-gcc -c ldap_query.c -o ldap_query.o
x86_64-w64-mingw32-gcc -c share_finder_bof.c -o share_finder_bof.o
x86_64-w64-mingw32-gcc -c esc1_finder_bof.c -o esc1_finder_bof.o
```

## Usage

```
demon> inline-execute /path/to/whoami_bof.o
demon> inline-execute /path/to/ldap_query.o
demon> inline-execute /path/to/share_finder_bof.o
demon> inline-execute /path/to/esc1_finder_bof.o
```

## Requirements

- Havoc C2
- Domain-joined system
- Valid domain credentials (uses current session context)

## Disclaimer

These tools are intended **exclusively for authorized security testing** in controlled lab environments. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

## License

MIT
