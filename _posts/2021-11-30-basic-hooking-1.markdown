---
title:  "Windows API hooking. Simple C++ example."
date:   2021-11-30 10:00:00 +0600
header:
  teaser: "/assets/images/27/2021-11-30_17-00.png"
categories:
  - tutorial
tags:
  - api hooking
  - windows
  - malware
  - red team
---

﷽

Hello, cybersecurity enthusiasts and white hackers!

![api hooking](/assets/images/27/2021-11-30_17-00.png){:class="img-responsive"}    

### what is API hooking?

API hooking is a technique by which we can instrument and modify the behaviour and flow of API calls. This technique is also used by many AV solutions to detect if code is malicious.   

### example 1

Before hooking windows API functions I will consider the case of how to do this with an exported function from a DLL.  

For example we have DLL with this logic (`pet.cpp`):
```cpp
/*
pet.dll - DLL example for basic hooking
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
  }
  return TRUE;
}

extern "C" {
  __declspec(dllexport) int _cdecl Cat(LPCTSTR say) {
    MessageBox(NULL, say, "=^..^=", MB_OK);
	  return 1;
	}
}

extern "C" {
  __declspec(dllexport) int _cdecl Mouse(LPCTSTR say) {
    MessageBox(NULL, say, "<:3()~~", MB_OK);
	  return 1;
	}
}

extern "C" {
  __declspec(dllexport) int _cdecl Frog(LPCTSTR say) {
    MessageBox(NULL, say, "8)~", MB_OK);
	  return 1;
	}
}

extern "C" {
  __declspec(dllexport) int _cdecl Bird(LPCTSTR say) {
    MessageBox(NULL, say, "<(-)", MB_OK);
	  return 1;
	}
}
```

As you can see this DLL have simplest exported functions: `Cat`, `Mouse`, `Frog`, `Bird` with one param `say`. As you can see the logic of this functions is simplest, just pop-up message with title.       

Let's go to compile it:   
```bash
x86_64-w64-mingw32-gcc -shared -o pet.dll pet.cpp -fpermissive
```

![api hooking 2](/assets/images/27/2021-11-30_17-30.png){:class="img-responsive"}    

and then, create a simple code to validate this DLL (`cat.cpp`):
```cpp
#include <windows.h>

typedef int (__cdecl *CatProc)(LPCTSTR say);
typedef int (__cdecl *BirdProc)(LPCTSTR say);

int main(void) {
  HINSTANCE petDll;
  CatProc catFunc;
  BirdProc birdFunc;
  BOOL freeRes;

  petDll = LoadLibrary("pet.dll");

  if (petDll != NULL) {
    catFunc = (CatProc) GetProcAddress(petDll, "Cat");
    birdFunc = (BirdProc) GetProcAddress(petDll, "Bird");
    if ((catFunc != NULL) && (birdFunc != NULL)) {
      (catFunc) ("meow-meow");
      (catFunc) ("mmmmeow");
      (birdFunc) ("tweet-tweet");
    }
    freeRes = FreeLibrary(petDll);
  }

  return 0;
}

```

Let's go to compile it:   
```bash
x86_64-w64-mingw32-g++ -O2 cat.cpp -o cat.exe -mconsole -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
```

![api hooking 3](/assets/images/27/2021-11-30_17-34.png){:class="img-responsive"}    

and run on `Windows 7 x64`:
```cmd
.\cat.exe
```

![api hooking 4](/assets/images/27/2021-11-30_17-37.png){:class="img-responsive"}    

![api hooking 5](/assets/images/27/2021-11-30_17-38.png){:class="img-responsive"}    

![api hooking 6](/assets/images/27/2021-11-30_18-02.png){:class="img-responsive"}    

and as you can see, everything works as expected.   

Then, for example `Cat` function will be hooked in this scenario, but it could be any.   

The workflow of this technique is as follows:   

First, get memory address of the `Cat` function.    

![api hooking 7](/assets/images/27/2021-11-30_18-05.png){:class="img-responsive"}    

then, save the first `5` bytes of the `Cat` function. We will need this bytes:

![api hooking 8](/assets/images/27/2021-11-30_18-07.png){:class="img-responsive"}    

then, create a `myFunc` function that will be executed when the original `Cat` is called:

![api hooking 9](/assets/images/27/2021-11-30_18-08.png){:class="img-responsive"}    

overwrite `5` bytes with a jump to `myFunc`:

![api hooking 10](/assets/images/27/2021-11-30_18-11.png){:class="img-responsive"}    

Then, create a "patch":    

![api hooking 11](/assets/images/27/2021-11-30_18-17.png){:class="img-responsive"}    

in the next step, patch our `Cat` function (redirect `Cat` function to `myFunc`):    

![api hooking 12](/assets/images/27/2021-11-30_18-19.png){:class="img-responsive"}    

So what have we done here? This trick is *"classic 5-byte hook"* technique. If we disassemble function:

![api hooking disas](/assets/images/27/2021-11-30_21-05.png){:class="img-responsive"}    

The highlighted `5` bytes is a fairly typical prologue found in many API functions. By overwriting these first `5` bytes with a `jmp` instruction, we are redirecting execution to our own defined function. We will save the original bytes so that they can be referenced later when we want to pass execution back to the hooked function.    

So firstly, we call original `Cat` function, set our hook and call `Cat` again:

![api hooking 13](/assets/images/27/2021-11-30_18-21.png){:class="img-responsive"}    

Full source code is:
```cpp
/*
hooking.cpp
basic hooking example
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/11/30/basic-hooking-1.html
*/
#include <windows.h>

typedef int (__cdecl *CatProc)(LPCTSTR say);

// buffer for saving original bytes
char originalBytes[5];

FARPROC hookedAddress;

// we will jump to after the hook has been installed
int __stdcall myFunc(LPCTSTR say) {
  HINSTANCE petDll;
  CatProc catFunc;

  // unhook the function: rewrite original bytes
  WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, originalBytes, 5, NULL);

  // return to the original function and modify the text
  petDll = LoadLibrary("pet.dll");
  catFunc = (CatProc) GetProcAddress(petDll, "Cat");

  return (catFunc) ("meow-squeak-tweet!!!");
}

// hooking logic
void setMySuperHook() {
  HINSTANCE hLib;
  VOID *myFuncAddress;
  DWORD *rOffset;
  DWORD src;
  DWORD dst;
  CHAR patch[5]= {0};

  // get memory address of function Cat
  hLib = LoadLibraryA("pet.dll");
  hookedAddress = GetProcAddress(hLib, "Cat");

  // save the first 5 bytes into originalBytes (buffer)
  ReadProcessMemory(GetCurrentProcess(), (LPCVOID) hookedAddress, originalBytes, 5, NULL);

  // overwrite the first 5 bytes with a jump to myFunc
  myFuncAddress = &myFunc;

  // will jump from the next instruction (after our 5 byte jmp instruction)
  src = (DWORD)hookedAddress + 5;
  dst = (DWORD)myFuncAddress;
  rOffset = (DWORD *)(dst-src);

  // \xE9 - jump instruction
  memcpy(patch, "\xE9", 1);
  memcpy(patch + 1, &rOffset, 4);

  WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, patch, 5, NULL);

}

int main() {
  HINSTANCE petDll;
  CatProc catFunc;

  petDll = LoadLibrary("pet.dll");
  catFunc = (CatProc) GetProcAddress(petDll, "Cat");

  // call original Cat function
  (catFunc)("meow-meow");

  // install hook
  setMySuperHook();

  // call Cat function after install hook
  (catFunc)("meow-meow");

}

```

Let's go to compile this:
```bash
x86_64-w64-mingw32-g++ -O2 hooking.cpp -o hooking.exe -mconsole -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
```

![api hooking 14](/assets/images/27/2021-11-30_18-22.png){:class="img-responsive"}    

And see it in action (on `Windows 7 x64` in this case):
```cmd
.\hooking.exe
```

![api hooking 15](/assets/images/27/2021-11-30_18-25.png){:class="img-responsive"}    

![api hooking 16](/assets/images/27/2021-11-30_18-25_1.png){:class="img-responsive"}    

As you can see our hook is worked perfectly!! Cat goes `meow-squeak-tweet!!!` instead `meow-meow`!   

### example 2

Similarly, you can hook for example, a function `WinExec` from `kernel32.dll` (`hooking2.cpp`):   
```cpp
#include <windows.h>

// buffer for saving original bytes
char originalBytes[5];

FARPROC hookedAddress;

// we will jump to after the hook has been installed
int __stdcall myFunc(LPCSTR lpCmdLine, UINT uCmdShow) {

  // unhook the function: rewrite original bytes
  WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, originalBytes, 5, NULL);

  // return to the original function and modify the text
  return WinExec("calc", uCmdShow);
}

// hooking logic
void setMySuperHook() {
  HINSTANCE hLib;
  VOID *myFuncAddress;
  DWORD *rOffset;
  DWORD src;
  DWORD dst;
  CHAR patch[5]= {0};

  // get memory address of function MessageBoxA
  hLib = LoadLibraryA("kernel32.dll");
  hookedAddress = GetProcAddress(hLib, "WinExec");

  // save the first 5 bytes into originalBytes (buffer)
  ReadProcessMemory(GetCurrentProcess(), (LPCVOID) hookedAddress, originalBytes, 5, NULL);

  // overwrite the first 5 bytes with a jump to myFunc
  myFuncAddress = &myFunc;

  // will jump from the next instruction (after our 5 byte jmp instruction)
  src = (DWORD)hookedAddress + 5;
  dst = (DWORD)myFuncAddress;
  rOffset = (DWORD *)(dst-src);

  // \xE9 - jump instruction
  memcpy(patch, "\xE9", 1);
  memcpy(patch + 1, &rOffset, 4);

  WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, patch, 5, NULL);

}

int main() {

  // call original
  WinExec("notepad", SW_SHOWDEFAULT);

  // install hook
  setMySuperHook();

  // call after install hook
  WinExec("notepad", SW_SHOWDEFAULT);

}
```

Let's go to compile:
```bash
x86_64-w64-mingw32-g++ -O2 hooking2.cpp -o hooking2.exe -mconsole -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
```

![api hooking 17](/assets/images/27/2021-11-30_18-35.png){:class="img-responsive"}    

and run:   
```cmd
.\hooking2.exe
```

![api hooking 18](/assets/images/27/2021-11-30_18-38.png){:class="img-responsive"}    

So everything worked as expected.   

[Source code in Github](https://github.com/cocomelonc/2021-11-30-basic-hooking-1)   

[MessageBox](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox)    
[WinExec](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)    
[Exporting from DLL using __declspec](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport?view=msvc-170)    

> This is a practical case for educational purposes only.      

Thanks for your time, happy hacking and good bye!    
*PS. All drawings and screenshots are mine*
