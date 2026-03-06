<p align="center">
  <img src="https://img.shields.io/badge/Language-C%2B%2B17-blue.svg" alt="Language">
  <img src="https://img.shields.io/badge/Platform-Windows_x64-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

<h1 align="center">SuperInjectorLib</h1>

<p align="center">
  <strong>A high-performance, stealth-oriented C++ Manual Mapping DLL Injector.</strong><br>
  Bypasses standard Windows APIs to map DLLs directly into target process memory.
</p>

---

## 🚀 Quick Start
Everything you need to inject a DLL in 3 simple steps.

```cpp
#include "SuperInjector.h"

int main() {
    Process proc;
    SuperInjector injector;

    // 1. Attach to target process
    if (!proc.Attach("notepad.exe")) return 1;

    // 2. Map your DLL manually
    auto result = injector.ManualMap(proc, "module.dll");

    // 3. Success check
    if (result) {
        printf("Success! Base Address: 0x%llx\n", result->baseAddress);
    }

    return 0;
}

---

## 🛠️ How it Works
it performs a manual link-and-load process within the target process's context:



1. **Section Mapping**: Copies each PE section (`.text`, `.data`, `.rdata`, etc.) to its respective virtual offset.
2. **Base Relocation**: If the DLL isn't loaded at its preferred base, every absolute address in the code is patched to match the new location.
3. **Import Resolution**: It manually loads all dependent DLLs and fills the Import Address Table (IAT).
4. **TLS & SEH**: Ensures Thread Local Storage and Structured Exception Handling (x64) are correctly registered to prevent crashes.
5. **Stealth Operation**: Once the `DllMain` is called, it wipes the PE headers to hide the DLL from simple memory scanners.
