#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h.>

#define TARGET_PROCESS_NAME "DXM-Win64-Shipping.exe"

#define TARGET_INSTRUCTION_OFFSET 0xB60CCA

unsigned long long getTargetBaseAddress(HANDLE processHandle) {
   
    MODULEENTRY32 me;
    int ret = Module32First(processHandle, &me);
    /* list all module
    while (ret)
    {
        printf("%p\t\%s\n", me.modBaseAddr, me.szModule);
        ret = Module32Next(processHandle, &me);
    }
    */
    BYTE* modBaseAddr = me.modBaseAddr;
    unsigned long long baseAddr = (unsigned long long)modBaseAddr;
  
    return baseAddr;
}

void readMemTest(HANDLE processHandle, unsigned long long targetAddress) {
    unsigned char tmp[6] = {0};
   
    BOOL result =  ReadProcessMemory(processHandle,(LPCVOID)targetAddress,tmp,6,NULL);
    if (result) {
        printf("readMemTest success\n");
    }
    else {
        printf("readMemTest failed %d\n", GetLastError());
    }  
}

void writeNopToTargetMemAddress(HANDLE processHandle, unsigned long long targetAddress) {
    DWORD dwNewProt, dwOldProt;
    BYTE nopInstructions[6] = {144,144,144,144,144,144};
    VirtualProtectEx(processHandle, (LPVOID)targetAddress, 6, PAGE_EXECUTE_READWRITE, &dwOldProt);
    BOOL result = WriteProcessMemory(processHandle, (LPVOID)targetAddress, nopInstructions, 6, NULL);
    if (result) {
        printf("writeNopToTargetMemAddress success\n");
    }
    else {
        printf("writeNopToTargetMemAddress failed %d\n", GetLastError());
    }
    VirtualProtectEx(processHandle, (LPVOID)targetAddress, 6, dwOldProt, &dwNewProt);
}

DWORD GetProcessIDByName(const char* pName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
        return NULL;
    }
    PROCESSENTRY32 pe = { sizeof(pe) };
    for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
        //printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
        if (strcmp(pe.szExeFile, pName) == 0) {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
    }
    CloseHandle(hSnapshot);
    return 0;
}

int main()
{
    DWORD targetPid = GetProcessIDByName(TARGET_PROCESS_NAME);
    if (targetPid == 0) {
        printf("can not found target process\n");
        system("pause");
        return 0;
    }
    printf("target pid is %d\n", targetPid);
    HANDLE hForGetAddr = CreateToolhelp32Snapshot(8, targetPid);
    unsigned long long baseAddress = getTargetBaseAddress(hForGetAddr);
    printf("base addr is %p \n", baseAddress);
    printf("target addr is %p \n", baseAddress + TARGET_INSTRUCTION_OFFSET);
    unsigned long long targetAddress = baseAddress + TARGET_INSTRUCTION_OFFSET;
    printf("target addr is %p \n",targetAddress);
    HANDLE hForWriteMem = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    //readMemTest(h2, targetAddress);
    writeNopToTargetMemAddress(hForWriteMem, targetAddress);

    CloseHandle(hForGetAddr);
    CloseHandle(hForWriteMem);
    system("pause");
    return 0;
}






