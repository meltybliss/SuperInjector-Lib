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
#include "Injector.h"

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
