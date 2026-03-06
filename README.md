<p align="center">
  <img src="https://img.shields.io/badge/Language-C%2B%2B17-blue.svg" alt="Language">
  <img src="https://img.shields.io/badge/Platform-Windows_x64-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

<h1 align="center">SuperInjectorLib</h1>

<p align="center">
  <strong>A C++ Manual Mapping DLL Injector.</strong><br>
  Implements a manual PE loader to map DLLs directly into a target process.
</p>

---

# Overview

**SuperInjectorLib** is a C++ library that demonstrates how to perform **manual DLL mapping** on Windows.

Instead of relying on `LoadLibrary`, the library manually performs the steps normally handled by the Windows loader:

- PE header parsing
- Section mapping
- Base relocation
- Import Address Table resolution
- TLS callback execution
- x64 exception registration
- `DllMain` invocation

This project is designed for **educational purposes** to understand how the Windows PE loader works internally.

---

# Features

- Manual PE mapping
- Base relocation handling
- Import table resolution
- TLS callback execution
- x64 Structured Exception Handling (SEH) registration
- Remote shellcode execution
- Optional PE header wiping after injection

---

# Requirements

- Windows x64
- C++17
- Visual Studio 2019+ or compatible compiler

---

# Quick Start

Example usage:

```cpp
#include "SuperInjector.h"

int main() {

    Process proc;

    if (!proc.Attach("notepad.exe"))
        return 1;

    auto result = SuperInjector::ManualMap(proc, "module.dll");

    if (result) {
        printf("Success! Base Address: 0x%llx\n", result->baseAddress);
    }

    return 0;
}
