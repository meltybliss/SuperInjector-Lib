#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <string_view>
//for wrapping Windows api
class Process {
public:
	HANDLE hProcess;

	DWORD GetPidByName(const char* processName);

	DWORD GetMainThreadId();

	bool Attach(const char* processName);
	void Detach();


	template<typename T>
	bool Read(uintptr_t address, T* buffer) {
		return ReadProcessMemory(this->hProcess, (LPCVOID)address, buffer, sizeof(T), NULL);
	}

	template<typename T>
	bool Write(uintptr_t address, const T& val) {
		return WriteProcessMemory(this->hProcess, (LPVOID)address, &val, sizeof(T), nullptr) != 0;
	}

	DWORD pid() { return m_pid; }

	bool IsAttached() { return hProcess != NULL; }

	bool IsAlive() const;

private:

	DWORD m_pid;
	std::string m_processName;

};