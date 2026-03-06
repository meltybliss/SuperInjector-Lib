#include "Process.h"

DWORD Process::GetPidByName(const char* processName)
{
    DWORD pid = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

    }


    CloseHandle(hSnapshot);

    return pid;
}

DWORD Process::GetMainThreadId()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    DWORD mainThreadId = 0;
    ULONGLONG minCreateTime = MAXULONGLONG; // 一番古い時間を探す用

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == m_pid) {
                // ここではシンプルに「最初に見つかったスレッド」を返しているが、
                // 本来は作成時間を比較して一番古いやつを選ぶのが確実
                mainThreadId = te.th32ThreadID;
                break;
            }

        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return mainThreadId;

}

bool Process::Attach(const char* processName)
{
    DWORD pid = GetPidByName(processName);

    this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    m_pid = pid;
    m_processName = processName;


    return (this->hProcess != NULL);
}

void Process::Detach() {
    if (hProcess) {
        CloseHandle(hProcess);
        hProcess = NULL;
    }

    m_pid = 0;
}

bool Process::IsAlive() const {
    if (!hProcess) return false;

    DWORD code = 0;
    if (!GetExitCodeProcess(hProcess, &code)) return false;

    return code == STILL_ACTIVE;

}
