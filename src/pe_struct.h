#ifndef _PE_STRUCT_H
#define _PE_STRUCT_H

#if !defined(_PARSER_H)
#include "parser.h"
#include <Windows.h>
#endif

typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef char CHAR;
typedef short SHORT;
typedef long LONG;
typedef unsigned long long ULONGLONG;

#define IMAGE_SIZEOF_SHORT_NAME              8
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES     16
#define DLL_NAME_MAX_SIZE                    256
#define FUNCTION_NAME_MAX_SIZE               256
#define INVALID_ADDRESS                      0xFFFF
#define INVALID_ADDR                         0xFFFFFFFF


typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;



typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;


typedef struct _DLL_CHARACTERSTICS{
    char* IMAGE_DYNAMIC_BASE;
    char* DATA_EXECUTION_PREVENTION;
    char* STRUCTURED_EXCEPTION_HANDLER;
}DLL_CHARACTERSTICS;

typedef struct _BASE_ADDRESS{
    DWORD        ImageBaseAddress32;
    ULONGLONG    ImageBaseAddress64;
}BASE_ADDRESS;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _SIZE_STACKHEAP{
    DWORD              SizeOfStackReserve32;
    DWORD              SizeOfStackCommit32;
    DWORD              SizeOfHeapReserve32;
    DWORD              SizeOfHeapCommit32;
    ULONGLONG          SizeOfStackReserve64;
    ULONGLONG          SizeOfStackCommit64;
    ULONGLONG          SizeOfHeapReserve64;
    ULONGLONG          SizeOfHeapCommit64;
}SIZE_STACKHEAP;

typedef struct _OPTIONAL_HEADER{
    WORD           Magic;
    BYTE           MajorLinkerVersion;
    BYTE           MinorLinkerVersion;
    DWORD          SizeOfCode;  //? .text
    DWORD          SizeOfInitializedData; //? .data 
    DWORD          SizeOfUninitializedData; //? .bss 
    DWORD          AddressOfEntryPoint;
    DWORD          BaseOfCode;
    DWORD          BaseOfData;  //

    BASE_ADDRESS   Base;
    DWORD          SectionAlignment;
    DWORD          FileAlignment;
    WORD           MajorOperatingSystemVersion;
    WORD           MinorOperatingSystemVersion;
    WORD           MajorImageVersion;
    WORD           MinorImageVersion;
    WORD           MajorSubsystemVersion;
    WORD           MinorSubsystemVersion;
    DWORD          Win32VersionValue;
    DWORD          SizeOfImage;
    DWORD          SizeOfHeaders;
    DWORD          CheckSum;
    WORD           Subsystem;
    WORD           DllCharacteristics;
    SIZE_STACKHEAP StackHeap;
    DWORD          LoaderFlags;
    DWORD          NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];   
}OPTIONAL_HEADER;

typedef struct _NT_HEADER{
    DWORD             Signature;
    IMAGE_FILE_HEADER FileHeader;
    OPTIONAL_HEADER   OptionalHeader;
}NT_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


struct SECTION_LINK{
    BYTE  Name[0x08];
    DWORD VirtualAddress;
    DWORD SizeofRawData;
    DWORD PointerToRawData;
    double entropy_value;
    struct SECTION_LINK* next;
};


typedef struct {
    union{
        DWORD Characterstics;
        DWORD OriginalFirstThunk;
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
    DWORD OriginalFirstThunk_FOA;
    BYTE OriginalFirstThunk_SECTION_NAME[IMAGE_SIZEOF_SHORT_NAME];
    DWORD Name_FOA;
    BYTE Name_FOA_SECTION_NAME[IMAGE_SIZEOF_SHORT_NAME];
    DWORD FirstThunk_FOA;
    BYTE FirstThunk_FOA_SECTION_NAME[IMAGE_SIZEOF_SHORT_NAME];
}IMPORT_DESCRIPTOR;

typedef struct {
    unsigned short HintValue;
    char FunctionName[FUNCTION_NAME_MAX_SIZE];
    // char* FunctionName;
}IMPORT_BY_NAME;

#define ptr(x) (char*) x

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#endif