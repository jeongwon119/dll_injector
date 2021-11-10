#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <memoryapi.h>
#include <libloaderapi.h>
#include <processthreadsapi.h>


using namespace std;

int getPIDByName(string name) {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (!hProcessSnap) {
		cout << "CreateToolhelp32Snapshot ERROR!" << endl;
		return -1;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		cout << "Process32First ERROR!" << endl;
		CloseHandle(hProcessSnap);
		return -1;
	}

	do {
		wstring pn(pe32.szExeFile);
		string pname(pn.begin(), pn.end());

		if (name == pname) {
			cout << "==============================" << endl;
			_tprintf(TEXT("File name: %s\n"), pe32.szExeFile);
			_tprintf(TEXT("Process ID: %d\n"), pe32.th32ProcessID);
			_tprintf(TEXT("Thread Count: %d\n"), pe32.cntThreads);
			cout << "==============================" << endl;

			return pe32.th32ProcessID;
			break;
		}
		else {
			continue;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
}

int main() {
	string name;
	string dll;
	HANDLE hProcess = NULL;
	LPVOID pRemotebuf = NULL;
	HMODULE hMod = NULL;
	LPTHREAD_START_ROUTINE pThread = NULL;
	HANDLE hThread = NULL;


	cout << "dll을 삽입할 프로세스 이름을 입력해주세요: ";
	cin >> name;
	cout << "삽입할 dll의 경로(절대경로): ";
	cin >> dll;

	wstring dllpath(dll.begin(), dll.end());

	int pid = getPIDByName(name);

	while (1) {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hProcess) {
			cout << "OpenProcess ERROR!" << endl;
			CloseHandle(hProcess);
			break;
		}

		pRemotebuf = VirtualAllocEx(hProcess, NULL, sizeof(dll) + 1, MEM_COMMIT, PAGE_READWRITE);
		if (!pRemotebuf) {
			cout << "VirtualAllocEx Error!" << endl;
			break;
		}

		if (!WriteProcessMemory(hProcess, pRemotebuf, dllpath.c_str(), (dllpath.size() * sizeof(wchar_t)), NULL)) {
			cout << "WriteProcessMemory ERROR!" << endl;
		}

		hMod = GetModuleHandle(L"kernel32.dll");
		pThread = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
		if (!pThread) {
			cout << "GetProcAddress Error!" << endl;
			break;
		}

		hThread = CreateRemoteThreadEx(hProcess, NULL, 0, pThread, pRemotebuf, NULL, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
	}
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}