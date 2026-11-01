#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <string.h>

struct FlagMap {
    WORD flag;
    const char* name;
};

const struct FlagMap FileCharacteristicsTable[] = {
    { IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED" },
    { IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE" },
    { IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED" },
    { IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED" },
    { IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM" },
    { IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE" },
    { IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO" },
    { IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE" },
    { IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED" },
    { IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP" },
    { IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP" },
    { IMAGE_FILE_SYSTEM, "SYSTEM" },
    { IMAGE_FILE_DLL, "DLL" },
    { IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY" },
    { IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI" }
};

bool FormatTime(char* formattedTime, size_t stringSize, DWORD originalTime);
void PrintFileCharacteristics(WORD fileCharacteristics, int characteristicsTableSize);
void PrintSubSystem(WORD subSystem);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("ERROR: Please provide the PID of the running process to scan!\n");

        return -1;
    }

    if (argc > 2) {
        printf("ERROR: The program expects only 1 PID of a running process to scan!\n");

        return -1;
    }

    char* endPtr;
    errno = 0;

    long pid = strtol(argv[1], &endPtr, 10);

    if (endPtr == argv[1]) {
        printf("ERROR: PID must be a number!\n");

        return -1;
    }

    if (*endPtr != '\0') {
        printf("ERROR: PID must be a number! Some characters were found in your input!\n");

        return -1;
    }

    if (errno == ERANGE) {
        printf("ERROR: PID is too large to process! Please provide a correct PID!\n");

        return -1;
    }

    if (pid < 0) {
        printf("ERROR: PID must be a positive number!\n");

        return -1;
    }

    printf("\n========================================================================================\n");
    printf("                          Process & Memory Integrity Scanner                             \n");
    printf("========================================================================================\n");

    unsigned int scanCounter = 0;
    while (true) {
        scanCounter++;
        printf("Performing Scan.. %u!\n", scanCounter);

        printf("\n1) Running Process Analysis:\n");
        printf("-----------------------------------\n");
        printf("Getting a handle to the process of PID: %ld..\n", pid);
        HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);

        if (processHandle == NULL) {
            printf("    ERROR: Couldn't get a handle to the process of PID: %ld! Error Code: %lu\n", pid, GetLastError());
        
            return -1;
        }
        printf("    Done!\n");
        
        printf("\nGetting Process File Info..\n");
        wchar_t processPath[MAX_PATH];
        DWORD processPathSize = MAX_PATH;

        ULARGE_INTEGER processFileSize;
        if (QueryFullProcessImageNameW(processHandle, 0, processPath, &processPathSize)) {
            WIN32_FILE_ATTRIBUTE_DATA processFileInfo;
            if (GetFileAttributesExW(processPath, GetFileExInfoStandard, &processFileInfo)) {
                processFileSize.LowPart = processFileInfo.nFileSizeLow;
                processFileSize.HighPart = processFileInfo.nFileSizeHigh;
            } else {
                printf("    Couldn't Read File Attributes on Disk! Error Code: %lu\n", GetLastError());
            }
        } else {
            printf("    Couldn't Retrieve Process Executable Path! Error Code: %lu\n", GetLastError());
        }
        printf("    Process File Information Gathered Successfully!\n");
        printf("    Process File Size: %.2f KB (%llu Bytes)\n", (double)processFileSize.QuadPart / 1024.0, processFileSize.QuadPart);

        printf("\nLocating the Base Address Pointer..\n");

        HMODULE modulesHandle[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(processHandle, modulesHandle, sizeof(modulesHandle), &cbNeeded) == 0) {
            printf("    Failed to get the Base Address Pointer! Error Code: %lu\n", GetLastError());

            CloseHandle(processHandle);

            return -1;
        }

        BYTE* runningProcessBaseAddressPointer = (BYTE*)modulesHandle[0];
        printf("    Done! Base Address Pointer is: 0x%llX\n", (uintptr_t)runningProcessBaseAddressPointer);

        printf("\nDOS Header:\n");
        printf("-----------------------------------\n");
        
        printf("Locating the DOS Header..\n");
        IMAGE_DOS_HEADER runningProcessDosHeader;
        SIZE_T runningDosBytesRead;
        if (ReadProcessMemory(processHandle, (LPCVOID)runningProcessBaseAddressPointer, &runningProcessDosHeader, sizeof(IMAGE_DOS_HEADER), &runningDosBytesRead) == 0) {
            printf("    ERROR: Couldn't get the DOS Header! Error Code: %lu\n", GetLastError());

            CloseHandle(processHandle);

            return -1;
        }
        printf("    Done!\n");

        printf("\n- DOS Header Signature: ");
        if (runningProcessDosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            printf("0x%X (Invalid)\n", runningProcessDosHeader.e_magic);

            CloseHandle(processHandle);

            return -1;
        }
        printf("0x%X (Valid)\n", runningProcessDosHeader.e_magic);

        printf("- e_lfanew: ");
        if (runningProcessDosHeader.e_lfanew < 64) {
            printf("0x%lX (Invalid: Smaller than 64)\n", runningProcessDosHeader.e_lfanew);

            CloseHandle(processHandle);

            return -1;
        } else if ((runningProcessDosHeader.e_lfanew % 4) != 0) {
            printf("0x%lX (Invalid: Not aligned to 4)\n", runningProcessDosHeader.e_lfanew);

            CloseHandle(processHandle);

            return -1;
        } else if ((runningProcessDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > UINT32_MAX) {
            printf("0x%lX (Invalid: Overflow)\n", runningProcessDosHeader.e_lfanew);

            CloseHandle(processHandle);

            return -1;
        } else if (runningProcessDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32) > processFileSize.QuadPart) {
            printf("0x%lX (Invalid: Larger than the file itself)\n", runningProcessDosHeader.e_lfanew);

            CloseHandle(processHandle);

            return -1;
        }
        printf("0x%lX (Valid)\n", runningProcessDosHeader.e_lfanew);

        printf("\nNT Headers:\n");
        printf("-----------------------------------\n");

        printf("Locating the NT Headers..\n");
        printf("    1. 32-Bit NT Headers: ");
        IMAGE_NT_HEADERS32 runningProcessNTHeaders32;
        SIZE_T runningNt32BytesRead;

        if (ReadProcessMemory(processHandle, (LPCVOID)(runningProcessBaseAddressPointer + runningProcessDosHeader.e_lfanew), &runningProcessNTHeaders32, sizeof(IMAGE_NT_HEADERS32), &runningNt32BytesRead) == 0) {
            printf("    ERROR: Couldn't get NT Headers 32! Error Code: %lu\n", GetLastError());

            CloseHandle(processHandle);

            return -1;
        }
        printf("Done!\n");

        printf("    2. 64-bit NT Headers: ");
        IMAGE_NT_HEADERS64 runningProcessNTHeaders64;
        SIZE_T runningNt64BytesRead;

        if (ReadProcessMemory(processHandle, (LPCVOID)(runningProcessBaseAddressPointer + runningProcessDosHeader.e_lfanew), &runningProcessNTHeaders64, sizeof(IMAGE_NT_HEADERS64), &runningNt64BytesRead) == 0) {
            printf("    ERROR: Couldn't get NT Headers 64! Error Code: %lu\n", GetLastError());

            CloseHandle(processHandle);
            
            return -1;
        }
        printf("Done!\n");

        printf("\n- NT Headers Signature: ");
        if (runningProcessNTHeaders32.Signature != 0x4550) {
            printf("0x%lX (Invalid)\n", runningProcessNTHeaders32.Signature);

            CloseHandle(processHandle);

            return -1;
        }
        printf("0x%lX (Valid)\n", runningProcessNTHeaders32.Signature);

        printf("- Target Architecture: ");
        if (runningProcessNTHeaders32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            printf("I386\n");
        } else if (runningProcessNTHeaders32.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            printf("AMD64\n");
        } else if (runningProcessNTHeaders32.FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64) {
            printf("ARM64\n");
        } else {
            printf("Unknown!\n");

            CloseHandle(processHandle);

            return -1;
        }

        printf("- Compiled Time: ");
        char formattedTimeStamp[64];
        if (FormatTime(formattedTimeStamp, sizeof(formattedTimeStamp), runningProcessNTHeaders32.FileHeader.TimeDateStamp)) {
            printf("%ld (%s)\n", runningProcessNTHeaders32.FileHeader.TimeDateStamp, formattedTimeStamp);
        } else {
            printf("%ld\n", runningProcessNTHeaders32.FileHeader.TimeDateStamp);
        }

        printf("- Number of Sections: %d\n", runningProcessNTHeaders32.FileHeader.NumberOfSections);

        printf("- Characteristics: ");
        int characteristicsTableSize = 15;
        PrintFileCharacteristics(runningProcessNTHeaders32.FileHeader.Characteristics, characteristicsTableSize);

        printf("\nOptional Headers:\n");
        printf("-----------------------------------\n");

        WORD sizeOfOptionalHeader;
        printf("\n- Target Architecture: ");
        if (runningProcessNTHeaders32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            printf("PE32 (32-bit)\n");
            printf("- Entry Point: 0x%08lX\n", runningProcessNTHeaders32.OptionalHeader.AddressOfEntryPoint);
            printf("- Image Base: 0x%lX\n", runningProcessNTHeaders32.OptionalHeader.ImageBase);
            printf("- Section Alignment: %ld Bytes\n", runningProcessNTHeaders32.OptionalHeader.SectionAlignment);
            printf("- File Alignment: %ld Bytes\n", runningProcessNTHeaders32.OptionalHeader.FileAlignment);
            printf("- Sybsystem: ");
            PrintSubSystem(runningProcessNTHeaders32.OptionalHeader.Subsystem);
            printf("- Size of Image: %.2lf KB\n", (double)runningProcessNTHeaders32.OptionalHeader.SizeOfImage / 1024);
            printf("- Size of Headers: %ld Bytes\n", runningProcessNTHeaders32.OptionalHeader.SizeOfHeaders);
        
            sizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        } else if (runningProcessNTHeaders32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            printf("PE32+ (64-bit)\n");
            printf("- Entry Point: 0x%08lX\n", runningProcessNTHeaders64.OptionalHeader.AddressOfEntryPoint);
            printf("- Image Base: 0x%llX\n", runningProcessNTHeaders64.OptionalHeader.ImageBase);
            printf("- Section Alignment: %ld Bytes\n", runningProcessNTHeaders64.OptionalHeader.SectionAlignment);
            printf("- File Alignment: %ld Bytes\n", runningProcessNTHeaders64.OptionalHeader.FileAlignment);
            printf("- Sybsystem: ");
            PrintSubSystem(runningProcessNTHeaders64.OptionalHeader.Subsystem);
            printf("- Size of Image: %.2lf KB\n", (double)runningProcessNTHeaders64.OptionalHeader.SizeOfImage / 1024);
            printf("- Size of Headers: %ld Bytes\n", runningProcessNTHeaders64.OptionalHeader.SizeOfHeaders);
        
            sizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        } else {
            printf("Unknown!\n");

            CloseHandle(processHandle);

            return -1;
        }

        printf("\nSection Headers:\n");
        printf("-----------------------------------\n");

        printf("Calculating Section Headers's Address..\n");
        uintptr_t runningProcessSectionHeadersAddressPointer = (uintptr_t)runningProcessBaseAddressPointer + runningProcessDosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader;
        printf("    Done! Running Process's Section Headers Address: 0x%llX\n", runningProcessSectionHeadersAddressPointer);

        printf("Allocating Memory to Store the Sections..\n");
        size_t runningProcessSectionHeadersSize = runningProcessNTHeaders32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

        PIMAGE_SECTION_HEADER runningProcessSectionHeadersPointer = (PIMAGE_SECTION_HEADER)malloc(runningProcessSectionHeadersSize);
        if (runningProcessSectionHeadersPointer == NULL) {
            printf("    ERROR: Failed to allocate memory for section headers!\n");

            CloseHandle(processHandle);

            return -1;
        }
        printf("    Done!\n");

        printf("Copying the Section Headers into Memory..\n");
        SIZE_T runningSectionHeadersBytesRead;
        if (!ReadProcessMemory(processHandle, (LPCVOID)runningProcessSectionHeadersAddressPointer, runningProcessSectionHeadersPointer, runningProcessSectionHeadersSize, &runningSectionHeadersBytesRead)) {
            printf("    ERROR: Couldn't Read Section Headers! Error Code: %lu\n", GetLastError());

            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("    Done!\n");

        printf("Locating the .text Section..\n");
        PIMAGE_SECTION_HEADER runningProcessTextSection = NULL;

        for (int i = 0; i < runningProcessNTHeaders32.FileHeader.NumberOfSections; i++) {
            char sectionName[9] = { 0 };
            memcpy(sectionName, runningProcessSectionHeadersPointer[i].Name, 8);

            if (strcmp(sectionName, ".text") == 0) {
                runningProcessTextSection = &runningProcessSectionHeadersPointer[i];
                break;
            }
        }

        if (runningProcessTextSection == NULL) {
            printf("    ERROR: Couldn't Find the .text Section!\n");
            
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }

        printf("    .text Section Found!\n");
        printf("\n.text Section Info:\n");
        printf("- Virtual Address (RVA): 0x%08lX\n", runningProcessTextSection->VirtualAddress);
        printf("- Virtual Size: 0x%08lX (%lu Bytes)\n", runningProcessTextSection->Misc.VirtualSize, runningProcessTextSection->Misc.VirtualSize);
        printf("- Raw Data Size: 0x%08lX (%lu Bytes)\n", runningProcessTextSection->SizeOfRawData, runningProcessTextSection->SizeOfRawData);
        printf("- Raw Data Pointer: 0x%08lX\n", runningProcessTextSection->PointerToRawData);
        printf("- Characteristics: 0x%08lX\n", runningProcessTextSection->Characteristics);

        printf("\n-------------------------------------------------------------------------------------------------------------------------------------\n");

        printf("\n2) On-Disk File Analysis:\n");
        printf("-----------------------------------\n");

        printf("Getting a handle to the process file..\n");
        HANDLE diskFileHandle = CreateFileW(processPath, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (diskFileHandle == INVALID_HANDLE_VALUE) {
            printf("    ERROR: Couldn't get a handle to the process file! Error Code: %lu\n", GetLastError());

            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("    Done!\n");

        printf("Creating a File Mapping..\n");
        HANDLE diskFileMappingHandle = CreateFileMappingA(diskFileHandle, NULL, PAGE_READONLY, 0, 0, NULL);

        if (diskFileMappingHandle == NULL) {
            printf("    Couldn't create a file mapping! Error Code: %lu\n", GetLastError());

            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("    Done!\n");

        printf("Map View of File..\n");
        LPVOID mapViewPointer = MapViewOfFile(diskFileMappingHandle, FILE_MAP_READ, 0, 0, 0);

        if (mapViewPointer == NULL) {
            printf("    ERROR: Couldn't Map View of File! Error Code: %lu\n", GetLastError());

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("    Done!\n");

        printf("Calculating Base Pointer..\n");
        BYTE* diskBasePointer = (BYTE*)mapViewPointer;
        printf("    Done! Base Pointer: 0x%llX\n", (uintptr_t)diskBasePointer);

        printf("\nDOS Header:\n");
        printf("-----------------------------------\n");
        PIMAGE_DOS_HEADER diskDosHeaderPointer = (PIMAGE_DOS_HEADER)diskBasePointer;

        printf("\n- DOS Header Signature: ");
        if (diskDosHeaderPointer->e_magic != IMAGE_DOS_SIGNATURE) {
            printf("0x%X (Invalid)\n", diskDosHeaderPointer->e_magic);

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("0x%X (Valid)\n", diskDosHeaderPointer->e_magic);

        printf("- e_lfanew: ");
        if (diskDosHeaderPointer->e_lfanew < 64) {
            printf("0x%lX (Invalid: Smaller than 64)\n", diskDosHeaderPointer->e_lfanew);

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        } else if ((diskDosHeaderPointer->e_lfanew % 4) != 0) {
            printf("0x%lX (Invalid: Not aligned to 4)\n", diskDosHeaderPointer->e_lfanew);

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        } else if ((diskDosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > UINT32_MAX) {
            printf("0x%lX (Invalid: Overflow)\n", diskDosHeaderPointer->e_lfanew);

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        } else if (diskDosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > processFileSize.QuadPart) {
            printf("0x%lX (Invalid: Larger than the file itself)\n", diskDosHeaderPointer->e_lfanew);

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("0x%lX (Valid)\n", diskDosHeaderPointer->e_lfanew);

        printf("\nNT Headers:\n");
        printf("-----------------------------------\n");
        PIMAGE_NT_HEADERS32 diskNtHeaders32Pointer = (PIMAGE_NT_HEADERS32)(diskBasePointer + diskDosHeaderPointer->e_lfanew);

        printf("\n- NT Headers Signature: ");
        if (diskNtHeaders32Pointer->Signature != 0x4550) {
            printf("0x%lX (Invalid)\n", diskNtHeaders32Pointer->Signature);

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("0x%lX (Valid)\n", diskNtHeaders32Pointer->Signature);

        printf("- Target Architecture: ");
        if (diskNtHeaders32Pointer->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            printf("I386\n");
        } else if (diskNtHeaders32Pointer->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            printf("AMD64\n");
        } else if (diskNtHeaders32Pointer->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64) {
            printf("ARM64\n");
        } else {
            printf("Unknown!\n");

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }

        printf("- Compiled Time: ");
        char diskFormattedTimeStamp[64];
        if (FormatTime(diskFormattedTimeStamp, sizeof(diskFormattedTimeStamp), diskNtHeaders32Pointer->FileHeader.TimeDateStamp)) {
            printf("%ld (%s)\n", diskNtHeaders32Pointer->FileHeader.TimeDateStamp, diskFormattedTimeStamp);
        } else {
            printf("%ld\n", diskNtHeaders32Pointer->FileHeader.TimeDateStamp);
        }

        printf("- Number of Sections: %d\n", diskNtHeaders32Pointer->FileHeader.NumberOfSections);

        printf("- Characteristics: ");
        PrintFileCharacteristics(diskNtHeaders32Pointer->FileHeader.Characteristics, characteristicsTableSize);

        printf("\nOptional Headers\n");
        printf("-----------------------------------\n");

        printf("- Target Architecture: ");
        if (diskNtHeaders32Pointer->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            printf("PE32 (32-bit)\n");
            printf("- Entry Point: 0x%08lX\n", diskNtHeaders32Pointer->OptionalHeader.AddressOfEntryPoint);
            printf("- Image Base: 0x%lX\n", diskNtHeaders32Pointer->OptionalHeader.ImageBase);
            printf("- Section Alignment: %ld Bytes\n", diskNtHeaders32Pointer->OptionalHeader.SectionAlignment);
            printf("- File Alignment: %ld Bytes\n", diskNtHeaders32Pointer->OptionalHeader.FileAlignment);
            printf("- Subsystem: ");
            PrintSubSystem(diskNtHeaders32Pointer->OptionalHeader.Subsystem);
            printf("- Size of Image: %.2lf KB\n", (double)diskNtHeaders32Pointer->OptionalHeader.SizeOfImage / 1024);
            printf("- Size of Headers: %ld Bytes\n", diskNtHeaders32Pointer->OptionalHeader.SizeOfHeaders);
        } else if (diskNtHeaders32Pointer->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            printf("PE32+ (64-bit)\n");

            PIMAGE_NT_HEADERS64 diskNtHeaders64Pointer = (PIMAGE_NT_HEADERS64)diskNtHeaders32Pointer;
            printf("- Entry Point: 0x%08lX\n", diskNtHeaders64Pointer->OptionalHeader.AddressOfEntryPoint);
            printf("- Image Base: 0x%llX\n", diskNtHeaders64Pointer->OptionalHeader.ImageBase);
            printf("- Section Alignment: %ld Bytes\n", diskNtHeaders64Pointer->OptionalHeader.SectionAlignment);
            printf("- File Alignment: %ld Bytes\n", diskNtHeaders64Pointer->OptionalHeader.FileAlignment);
            printf("- Subsystem: ");
            PrintSubSystem(diskNtHeaders64Pointer->OptionalHeader.Subsystem);
            printf("- Size of Image: %.2lf KB\n", (double)diskNtHeaders64Pointer->OptionalHeader.SizeOfImage / 1024);
            printf("- Size of Headers: %ld Bytes\n", diskNtHeaders64Pointer->OptionalHeader.SizeOfHeaders);
        } else {
            printf("Unknown!\n");

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }

        printf("\nSection Headers:\n");
        printf("-----------------------------------\n");
        printf("Locating the .text Section..");
        PIMAGE_SECTION_HEADER diskSectionHeadersPointer = IMAGE_FIRST_SECTION(diskNtHeaders32Pointer);

        PIMAGE_SECTION_HEADER diskTextSectionPointer = NULL;
        for (int i = 0; i < diskNtHeaders32Pointer->FileHeader.NumberOfSections; i++) {
            char sectionName[9] = { 0 };
            memcpy(sectionName, diskSectionHeadersPointer[i].Name, 8);

            if (strcmp(sectionName, ".text") == 0) {
                diskTextSectionPointer = &diskSectionHeadersPointer[i];
                break;
            }
        }

        if (diskTextSectionPointer == NULL) {
            printf("    Couldn't find the .text section!\n");

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("    .text Section Found!\n");

        printf("\n.text Section Info:\n");
        printf("- Virtual Address (RVA): 0x%08lX\n", diskTextSectionPointer->VirtualAddress);
        printf("- Virtual Size: 0x%08lX (%lu Bytes)\n", diskTextSectionPointer->Misc.VirtualSize, diskTextSectionPointer->Misc.VirtualSize);
        printf("- Raw Data Size: 0x%08lX (%lu Bytes)\n", diskTextSectionPointer->SizeOfRawData, diskTextSectionPointer->SizeOfRawData);
        printf("- Raw Data Pointer: 0x%08lX\n", diskTextSectionPointer->PointerToRawData);
        printf("- Characteristics: 0x%08lX\n", diskTextSectionPointer->Characteristics);

        printf("\n-------------------------------------------------------------------------------------------------------------------------------------\n");

        printf("\n3) .text Section Comparison:\n");
        printf("-----------------------------------\n");

        DWORD bytesToCompare = (diskTextSectionPointer->SizeOfRawData < runningProcessTextSection->Misc.VirtualSize) ? diskTextSectionPointer->SizeOfRawData : runningProcessTextSection->Misc.VirtualSize;
        BYTE* cleanTextPointer = diskBasePointer + diskTextSectionPointer->PointerToRawData;
        
        printf("Allocating Memory to Copy the Running .Text Section..\n");
        BYTE* liveTextBuffer = (BYTE*)malloc(bytesToCompare);
        
        if (liveTextBuffer == NULL) {
            printf("    Failed to allocate memory to copy the running .text section!\n");

            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("    Done!\n");

        LPCVOID liveTextAddress = (LPCVOID)(runningProcessBaseAddressPointer + runningProcessTextSection->VirtualAddress);

        printf("Copying .text Section Data..\n");
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(processHandle, liveTextAddress, liveTextBuffer, bytesToCompare, &bytesRead)) {
            printf("    Couldn't read .text data! Error Code: %lu\n", GetLastError());

            free(liveTextBuffer);
            CloseHandle(diskFileMappingHandle);
            CloseHandle(diskFileHandle);
            free(runningProcessSectionHeadersPointer);
            CloseHandle(processHandle);

            return -1;
        }
        printf("    Done!\n");

        printf("\nComparing %lu bytes between disk and RAM..\n", bytesToCompare);
        DWORD mismatchCount = 0;

        for (DWORD i = 0; i < bytesToCompare; i++) {
            if (cleanTextPointer[i] != liveTextBuffer[i]) {
                mismatchCount++;
                uintptr_t mismatchRVA = runningProcessTextSection->VirtualAddress + i;

                printf("    ALERT: Memory corruption/hook detected at RVA 0x%08llX!\n", mismatchRVA);
                printf("        - Clean Version: 0x%02X\n", cleanTextPointer[i]);
                printf("        - Live Version: 0x%02X\n", liveTextBuffer[i]);
            }
        }

        printf("    Comparison is Complete: ");
        if (mismatchCount == 0) {
            printf("No modifications found in .text section!\n");
        } else {
            printf("Found %lu byte discrepancies!\n", mismatchCount);
        }

        printf("\nCleaning..\n");
        
        free(liveTextBuffer);
        CloseHandle(diskFileMappingHandle);
        CloseHandle(diskFileHandle);
        free(runningProcessSectionHeadersPointer);
        CloseHandle(processHandle);

        Sleep(2000);
    }
    
    return 0;
}

bool FormatTime(char* formattedTime, size_t stringSize, DWORD originalTime) {
    time_t rawTime = (time_t)originalTime;
    struct tm *utc_time;

    utc_time = gmtime(&rawTime);

    if (utc_time == NULL) {
        printf("Couldn't format the date!\n");

        return false;
    }

    size_t result = strftime(formattedTime, stringSize, "%a %b %d %H:%M:%S %Y UTC", utc_time);
    
    if (result == 0) {
        return false;
    }

    return true;
}

void PrintFileCharacteristics(WORD fileCharacteristics, int characteristicsTableSize) {
    BOOL isFirst = TRUE;

    printf("0x%X (", fileCharacteristics);
    for (int i = 0; i < characteristicsTableSize; i++) {
        if ((fileCharacteristics & FileCharacteristicsTable[i].flag) == FileCharacteristicsTable[i].flag) {
            if (!isFirst) {
                printf(", ");
            }

            printf("%s", FileCharacteristicsTable[i].name);
            isFirst = FALSE;
        }
    }

    if (isFirst) {
        printf("None");
    }
    printf(")\n");
}

void PrintSubSystem(WORD subSystem) {
    if (subSystem == IMAGE_SUBSYSTEM_UNKNOWN) {
        printf("Unknown\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_NATIVE) {
        printf("Device Driver / Native System Process\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
       printf("Windows GUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        printf("Windows CUI (Console)\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_OS2_CUI) {
        printf("OS/2 CUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_POSIX_CUI) {
        printf("POSIX CUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) {
        printf("Windows CE System\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_APPLICATION) {
        printf("EFI Application\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
        printf("EFI Driver with Boot Services\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
        printf("EFI Driver with Run-Time Services\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_ROM) {
        printf("EFI ROM Image\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_XBOX) {
        printf("Xbox System\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION) {
        printf("Windows Boot Application\n");
    }
}