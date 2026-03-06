#include "Injector.h"
#include <iostream>


void __stdcall ShellCode(MANUAL_MAPPING_DATA* pData);
void __stdcall ShellCode_End();

bool SuperInjector::InjectAndExecute(Process& proc, const std::vector<unsigned char>& shellCode) {
	if (!proc.IsAttached() || !proc.IsAlive() || shellCode.empty()) return false;


	//後にこれはWindowsAPIの代わりに秘匿性の高い処理に変える


	//STEP 1: ターゲットプロセス内に「空き地」を確保
	// PAGE_EXECUTE_READWRITE を指定することで、書いたコードを実行可能にする
	void* remoteMem = VirtualAllocEx(
		proc.hProcess,
		nullptr,
		shellCode.size(),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!remoteMem) {
		ReportError("VirtualAllocEx failed");
		return false;
	}

	//STEP 2: 確保した場所にバイナリ（機械語）を書き込む
	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(
		proc.hProcess,
		remoteMem,
		shellCode.data(),
		shellCode.size(),
		&bytesWritten
	)) {
		ReportError("WriteProcessMem failed");
		VirtualFreeEx(proc.hProcess, remoteMem, 0, MEM_RELEASE);
		return false;
	}
	//STEP 3: 遠隔でスレッドを作成し、実行スイッチを入れる ---
	// ターゲットプロセスの CPU に対し「remoteMem の住所から処理を始めて！」と命令する


	HANDLE hThread = CreateRemoteThread(
		proc.hProcess,
		nullptr,
		0,
		(LPTHREAD_START_ROUTINE)remoteMem,
		nullptr,
		0,
		nullptr
	);

	if (!hThread) {
		ReportError("CreateRemoteThread failed");
		VirtualFreeEx(proc.hProcess, remoteMem, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);


	return true;
}

std::optional<SuperInjector::InjectResult> SuperInjector::ManualMap(Process& proc, std::filesystem::path dllPath)
{
	if (!std::filesystem::exists(dllPath)) return std::nullopt;

	// 後片付けのためにポインタを null で初期化しておく
	void* targetBase = nullptr;
	void* pMappingDataAlloc = nullptr;
	void* pShellCodeAlloc = nullptr;

	auto cleanup = [&]() {
		if (targetBase) VirtualFreeEx(proc.hProcess, targetBase, 0, MEM_RELEASE);
		if (pMappingDataAlloc) VirtualFreeEx(proc.hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
		if (pShellCodeAlloc) VirtualFreeEx(proc.hProcess, pShellCodeAlloc, 0, MEM_RELEASE);
	};


	std::cout << "[*] Loading DLL: " << dllPath << std::endl;
	//DLLファイルをバイナリとして読み込む
	std::ifstream file(dllPath, std::ios::binary | std::ios::ate);//ate mode
	if (file.fail()) return std::nullopt;

	size_t fileSize = file.tellg();
	std::vector<uint8_t> rawData(fileSize);
	file.seekg(0, std::ios::beg);
	file.read((char*)rawData.data(), fileSize);
	file.close();

	// 2. PEヘッダーの確認（これが正しいDLLファイルかチェック）
	auto* dosHeader = (PIMAGE_DOS_HEADER)rawData.data();
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

	auto* ntHeader = (PIMAGE_NT_HEADERS)(rawData.data() + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

	// 3. メモリ確保
	targetBase = VirtualAllocEx(proc.hProcess, nullptr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (!targetBase) { std::cout << "[-] VirtualAllocEx Failed!" << std::endl; return std::nullopt; }

	std::cout << "[+] TargetBase Allocated at: " << targetBase << std::endl;

	std::cout << "[*] Writing PE Headers..." << std::endl;
	if (!WriteProcessMemory(proc.hProcess, targetBase, rawData.data(), ntHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
		std::cout << "[-] Failed to write PE Headers!" << std::endl;
		cleanup();
		return std::nullopt;
	}

	// 4. セクションのコピー
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
		if (pSectionHeader[i].SizeOfRawData > 0) {
			void* dest = (uint8_t*)targetBase + pSectionHeader[i].VirtualAddress;
			void* src = rawData.data() + pSectionHeader[i].PointerToRawData;

			std::cout << "[*] Writing Section: " << i << std::endl;
			if (!WriteProcessMemory(proc.hProcess, dest, src, pSectionHeader[i].SizeOfRawData, nullptr)) {
				std::cout << "[-] Failed to write Section!" << std::endl;
				cleanup();
				return std::nullopt;
			}
		}
	}
	
	MANUAL_MAPPING_DATA data{ 0 };

	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;

	// 2. 64bit特有の例外処理関数の住所を取得
#ifdef _WIN64
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32) {
		data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)GetProcAddress(hKernel32, "RtlAddFunctionTable");
	}
#endif

	data.pbase = (BYTE*)targetBase;
	data.fdwReasonParam = DLL_PROCESS_ATTACH;
	data.reservedParam = nullptr;
	data.SEHSupport = TRUE; 
	data.hMod = NULL; 

	// ターゲットプロセス内に構造体用のメモリを確保
	pMappingDataAlloc = VirtualAllocEx(proc.hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMappingDataAlloc) { cleanup(); return std::nullopt; }

	if (!WriteProcessMemory(proc.hProcess, pMappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		cleanup(); return std::nullopt;
	}

	pShellCodeAlloc = VirtualAllocEx(proc.hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellCodeAlloc) { cleanup(); return std::nullopt; }

	// 関数のサイズを正しく計算して書き込む
	size_t codeSize = (uintptr_t)ShellCode_End - (uintptr_t)ShellCode;
	if (codeSize <= 0 || codeSize > 0x1000) codeSize = 0x1000;

	//定義したShellcode 関数をターゲットに書き込む. Shellcode関数をそのままコピーして送り込む
	if (!WriteProcessMemory(proc.hProcess, pShellCodeAlloc, (void*)ShellCode, codeSize, nullptr)) {
		cleanup(); return std::nullopt;
	}

	//Thread
	std::cout << "[*] Thread..." << std::endl;

	HANDLE hThread = CreateRemoteThread(proc.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellCodeAlloc, pMappingDataAlloc, 0, nullptr);
    if (!hThread) { cleanup(); return std::nullopt; }
    CloseHandle(hThread);


	std::cout << "[+] Thread. Waiting for response..." << std::endl;

	////

	HINSTANCE hCheck = NULL;
	const int timeoutMs = 10000; // 10秒待ってダメなら諦める
	int elapsed = 0;

	while (elapsed < timeoutMs) {
		MANUAL_MAPPING_DATA data_checked{ 0 };

		if (!ReadProcessMemory(proc.hProcess, pMappingDataAlloc, &data_checked, sizeof(data_checked), nullptr)) {
			cleanup(); return std::nullopt;
		}
		
		hCheck = data_checked.hMod;

		if (hCheck != (HINSTANCE)0x0) {
			printf("\r[*] ShellCode Status: 0x%p", (void*)hCheck);
		}

		if (hCheck == (HINSTANCE)targetBase) { // 住所が完全に一致した時だけ成功とみなす
			printf("\n[+] Success! DLL Base: %p\n", hCheck);

			//（ヘッダー消去）
			DWORD old;
			VirtualProtectEx(proc.hProcess, targetBase, 0x1000, PAGE_READWRITE, &old);
			std::vector<uint8_t> zeroBuffer(0x1000, 0);
			WriteProcessMemory(proc.hProcess, targetBase, zeroBuffer.data(), zeroBuffer.size(), nullptr);

			VirtualProtectEx(proc.hProcess, targetBase, ntHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READ, &old);

			data_checked.hMod = (HINSTANCE)0xDEADBEEF;
			WriteProcessMemory(proc.hProcess, pMappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
			break;
		}
		
		if (data_checked.hMod != 0) {
			printf("\r[*] Raw hMod Value: %p", data_checked.hMod);
		}
		Sleep(100);
		elapsed += 100;
	}

	if (hCheck != (HINSTANCE)targetBase) {
		cleanup();
		return std::nullopt;
	}

	printf("DLL Mapping Successful! At: %p\n", hCheck);

	VirtualFreeEx(proc.hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
	VirtualFreeEx(proc.hProcess, pShellCodeAlloc, 0, MEM_RELEASE);

	InjectResult result;
	result.baseAddress = (uintptr_t)hCheck;
	result.status = L"Injection Successful and Initialized.";

	return result;

}

void SuperInjector::ReportError(const char* msg)
{
	std::cerr << "[Injector Error] " << msg << " | Code: " << GetLastError() << "\n";
}

#pragma runtime_checks("", off)
#pragma optimize("", off)

void __stdcall ShellCode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) return;

	// --- STEP 1: 初期化開始 ---
	pData->hMod = (HINSTANCE)0x1;

	BYTE* pBase = pData->pbase;
	auto* pDos = (PIMAGE_DOS_HEADER)pBase;
	auto* pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
	auto* pOpt = &pNt->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);

	typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(HINSTANCE, DWORD, LPVOID);

	// 1. 再配置 (Relocation)
	pData->hMod = (HINSTANCE)0x2;
	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta != 0) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = (IMAGE_BASE_RELOCATION*)((uintptr_t)pRelocData + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = (WORD*)(pRelocData + 1);
				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if ((*pRelativeInfo >> 12) == 10) { // DIR64 (64bit)
						uintptr_t* pPatch = (uintptr_t*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += (uintptr_t)LocationDelta;
					}
					else if ((*pRelativeInfo >> 12) == 3) { // HIGHLOW (32bit)
						DWORD* pPatch = (DWORD*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += (DWORD)(uintptr_t)LocationDelta;
					}
				}
				pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)pRelocData + pRelocData->SizeOfBlock);
			}
		}
	}

	// 2. インポート解決 (Import Resolution)

	pData->hMod = (HINSTANCE)0x3;
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = (char*)(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);
			ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);
			if (!pImportDescr->OriginalFirstThunk) pThunkRef = pFuncRef;
			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			pImportDescr++;
		}
	}

	// 3. TLSコールバックの実行 (これがないと落ちるDLLが多い)
	pData->hMod = (HINSTANCE)0x4;
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	// 4. SEH（例外処理）の登録 (64bit環境で必須)
#ifdef _WIN64
	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			pData->pRtlAddFunctionTable(
				(PRUNTIME_FUNCTION)(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase);
		}
	}
#endif

	// 5. DllMainの呼び出し
	pData->hMod = (HINSTANCE)0x5;

	// 型を明示的にキャストして呼び出す
	f_DLL_ENTRY_POINT _RealDllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);
	_RealDllMain((HINSTANCE)pBase, pData->fdwReasonParam, pData->reservedParam);


	// 呼び出しが終わったら成功報告
	pData->hMod = (HINSTANCE)pBase;

	while (pData->hMod != (HINSTANCE)0xDEADBEEF) {
		// スリープ代わりの空ループ。実際は Sleep をインポートして呼ぶのがベスト
	}
}
// ShellCode の終わりをマークするダミー関数
void __stdcall ShellCode_End() {}