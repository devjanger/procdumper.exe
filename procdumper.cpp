#include <stdio.h>
#include <windows.h>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

using namespace std;

void ProcessDumpToFile(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to open process. Error: %lu\n", GetLastError());
        exit(-1);
    }

    FILE* dumpFile;
    string filename = to_string(pid) + ".DMP";

    if (fopen_s(&dumpFile, filename.c_str(), "wb") != 0) {
        printf("Failed to create dump file.\n");
        CloseHandle(hProcess);
        exit(-1);
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPCVOID address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T bytesRead;
    unsigned char* buffer = (unsigned char*)malloc(4096);

    while (address < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                !(mbi.Protect & PAGE_GUARD)) {

                SIZE_T regionSize = mbi.RegionSize;
                unsigned char* regionBuffer = (unsigned char*)malloc(regionSize);
                if (regionBuffer) {
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, regionBuffer, regionSize, &bytesRead)) {
                        fwrite(regionBuffer, 1, bytesRead, dumpFile);
                    }
                    free(regionBuffer);
                }
            }
            address = (LPCVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
        }
        else {
            break;
        }
    }

    free(buffer);
    fclose(dumpFile);
    CloseHandle(hProcess);

    printf("Memory dump complete: %s\n", filename.c_str());
}

vector<int> GetPIDSByName(const wchar_t* processName) {

    vector<int> pids;


    PROCESSENTRY32W pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return pids;
    }

    do {

        if (_wcsicmp(pe32.szExeFile, processName) == 0) {
            pids.push_back(pe32.th32ProcessID);
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pids;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <process name>", argv[0]);
        return 1;
    }

    wstring targetProcess(argv[1], argv[1] + std::strlen(argv[1]));
    vector<int> pids = GetPIDSByName(targetProcess.c_str());

    if (pids.size() <= 0 || pids.empty())
    {
        wprintf(L"'%s' process not found.", targetProcess.c_str());
        return 0;
    }

    for (int pid : pids)
    {
        printf("PID: %d dummping..\n", pid);
        ProcessDumpToFile(pid);
    }
	
	return 0;
}
