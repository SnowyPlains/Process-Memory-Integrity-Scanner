# Process & Memory Integrity Scanner
#### A continuous user-mode defensive security daemon written in pure C utilizing the Win32 API to monitor, audit, and detect dynamic runtime code modifications inside running Windows processes.

#### Designed as an anti-cheat and endpoint security primitive, this tool continuously inspects target memory spaces, performs dual-context Portable Executable (PE) header parsing across remote process virtual memory and clean disk mappings, and runs byte-level differential scans to catch tampering, code caves, or dynamic patches.

#### Date: 1 November 2026

## Core Problem Space:
Modern security monitoring faces a fundamental verification challenge: how do you trust what is executing in memory? This engine addresses three major security challenges:
1) **Runtime Memory Tampering:** Once a legitimate binary is mapped into virtual memory, co-privileged software, cheats, or malware can dynamically patch instruction bytes directly into the executable code section without modifying the original binary on disk.
2) **The Disk vs. RAM Divergence:** Attackers assume that security monitoring tools only inspect static files on disk. By continuously contrasting the live .text section in RAM against a pristine, memory-mapped representation of the file from disk, this discrepancy is immediately exposed.
3) **Continuous Daemonized Polling:** Real-time defense requires continuous background auditing rather than a one-off inspection, ensuring that runtime injections or modifications executed mid-lifecycle are caught during scheduled heartbeat intervals.

## Architecture & Execution Flow:
Operating as a continuous user-mode telemetry and integrity scanner, the tool loops through a robust multi-stage analysis pipeline:
1) **Target Process Attachment:** Opens a secure handle to a target Process ID with specific access rights (PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION).
2) **Path Resolution & Image Data:** Automatically resolves the full executable image file path from the remote process handle and gathers file attributes.
3) **Live Remote PE Parsing:** Enumerates process modules to locate the true runtime base address pointer, reads and validates remote DOS headers, checks NT signature integrity, and parses dynamic PE structures via ReadProcessMemory to isolate the live .text section.
4) **Clean Disk Mapping:** Opens the exact executable file from disk using Win32 file handles, creates a memory mapping object (CreateFileMappingA), maps a clean view of the file (MapViewOfFile), and parses its disk-based PE headers and section table.
5) **Differential Byte-by-Byte Engine:** Calculates the safe comparison boundary, allocates a local buffer, safely streams live process memory bytes via ReadProcessMemory, and executes an exact byte-level differential scan against the clean disk representation.
6) **RVA Discrepancy Reporting:** If a modification or hook is detected, calculates the exact Relative Virtual Address (RVA) of corruption and prints detailed comparisons showing clean vs. live byte hex values.
7) **Continuous Daemon Loop:** Cleans up allocated resources, sleeps for a configured interval, and repeats the entire audit cycle indefinitely.

## Technical Implementation Highlights:
- **Pure C & Win32 Native:** Developed entirely from scratch using raw Win32 APIs, file mapping primitives, and standard C libraries without third-party frameworks.
- **Dual-Context PE Resolution:** Simultaneously parses and navigates two distinct memory domains: the remote live target process space and the local memory-mapped file view.
- **Safe Boundary Management:** Implements rigorous bounds-checking and size clipping to prevent out-of-bounds memory reads during section comparisons.
- **Robust Resource Management:** Ensures meticulous handle closure and memory deallocation on every single loop iteration to prevent leaks during continuous background operation.

## Compilation & Usage:
**Prerequisites:**  
- Any C standard compliant compiler such as gcc, clang, ...

**Build Instructions Example Using GCC:**
- gcc -Wall -Wextra -O3 main.c -o MemIntegrityScanner

*MemIntegrityScanner is the name of the program, you can name it anything you want

**Execution Examples:**
- **General Syntax:** .\MemIntegrityScanner.exe \<pid\>
- **Example:** .\MemIntegrityScanner.exe 3068

## Sample Output:
```
========================================================================================
                          Process & Memory Integrity Scanner                             
========================================================================================
Performing Scan.. 1!

1) Running Process Analysis:
-----------------------------------
Getting a handle to the process of PID: 11944..
    Done!

Getting Process File Info..
    Process File Information Gathered Successfully!
    Process File Size: 90.29 KB (92455 Bytes)

Locating the Base Address Pointer..
    Done! Base Address Pointer is: 0x7FF655670000

DOS Header:
-----------------------------------
Locating the DOS Header..
    Done!

- DOS Header Signature: 0x5A4D (Valid)
- e_lfanew: 0x80 (Valid)

NT Headers:
-----------------------------------
Locating the NT Headers..
    1. 32-Bit NT Headers: Done!
    2. 64-bit NT Headers: Done!

- NT Headers Signature: 0x4550 (Valid)
- Target Architecture: AMD64
- Compiled Time: 1793444352 (Sat Oct 31 10:59:12 2026 UTC)
- Number of Sections: 18
- Characteristics: 0x26 (EXECUTABLE_IMAGE, LINE_NUMS_STRIPPED, LARGE_ADDRESS_AWARE)

Optional Headers:
-----------------------------------

- Target Architecture: PE32+ (64-bit)
- Entry Point: 0x0000105F
- Image Base: 0x7FF655670000
- Section Alignment: 4096 Bytes
- File Alignment: 512 Bytes
- Sybsystem: Windows CUI (Console)
- Size of Image: 112.00 KB
- Size of Headers: 1536 Bytes

Section Headers:
-----------------------------------
Calculating Section Headers's Address..
    Done! Running Process's Section Headers Address: 0x7FF655670188
Allocating Memory to Store the Sections..
    Done!
Copying the Section Headers into Memory..
    Done!
Locating the .text Section..
    .text Section Found!

.text Section Info:
- Virtual Address (RVA): 0x00001000
- Virtual Size: 0x00008700 (34560 Bytes)
- Raw Data Size: 0x00008800 (34816 Bytes)
- Raw Data Pointer: 0x00000600
- Characteristics: 0x60000020

-------------------------------------------------------------------------------------------------------------------------------------

2) On-Disk File Analysis:
-----------------------------------
Getting a handle to the process file..
    Done!
Creating a File Mapping..
    Done!
Map View of File..
    Done!
Calculating Base Pointer..
    Done! Base Pointer: 0x28543B60000

DOS Header:
-----------------------------------

- DOS Header Signature: 0x5A4D (Valid)
- e_lfanew: 0x80 (Valid)

NT Headers:
-----------------------------------

- NT Headers Signature: 0x4550 (Valid)
- Target Architecture: AMD64
- Compiled Time: 1793444352 (Sat Oct 31 10:59:12 2026 UTC)
- Number of Sections: 18
- Characteristics: 0x26 (EXECUTABLE_IMAGE, LINE_NUMS_STRIPPED, LARGE_ADDRESS_AWARE)

Optional Headers
-----------------------------------
- Target Architecture: PE32+ (64-bit)
- Entry Point: 0x0000105F
- Image Base: 0x140000000
- Section Alignment: 4096 Bytes
- File Alignment: 512 Bytes
- Subsystem: Windows CUI (Console)
- Size of Image: 112.00 KB
- Size of Headers: 1536 Bytes

Section Headers:
-----------------------------------
Locating the .text Section..    .text Section Found!

.text Section Info:
- Virtual Address (RVA): 0x00001000
- Virtual Size: 0x00008700 (34560 Bytes)
- Raw Data Size: 0x00008800 (34816 Bytes)
- Raw Data Pointer: 0x00000600
- Characteristics: 0x60000020

-------------------------------------------------------------------------------------------------------------------------------------

3) .text Section Comparison:
-----------------------------------
Allocating Memory to Copy the Running .Text Section..
    Done!
Copying .text Section Data..
    Done!

Comparing 34560 bytes between disk and RAM..
    Comparison is Complete: No modifications found in .text section!

Cleaning..
Performing Scan.. 2!

...
```

## Notes:
This project is intended for educational, research, defensive security engineering, and anti-cheat development purposes.

## References:
1) [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
2) [OpenProcess Security Flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
3) [EnumProcessModules](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)
4) [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
5) [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
6) [CreateFileMappingA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
7) [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)