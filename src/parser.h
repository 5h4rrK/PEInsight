#ifndef _PARSER_H
#define _PARSER_H

#if !defined(_WINDOWS_)
// #include "../../mbase_memory/m_os_inc.h"
#include "pe_struct.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#endif 

#define IMAGE_FILE_MACHINE_RISCV32          0x5032
#define IMAGE_FILE_MACHINE_RISCV64          0x5064
#define IMAGE_FILE_MACHINE_LOONGARCH32      0x6232
#define IMAGE_FILE_MACHINE_LOONGARCH64      0x6264

void parse_section_headers        (FILE* fp);
void parse_nt_headers             (FILE* fp);
void parse_dos_stub               (FILE* fp);
void parse_dosheader              (FILE* fp);
void parse_structure              (FILE* fp);
void machine_arch                 (FILE* fp);
void print_dos_headers            (const IMAGE_DOS_HEADER* dosheader);
// void dump_section                 (FILE* fp, const IMAGE_SECTION_HEADER* section, struct SECTION_LINK* seclink);

static inline void read_and_print_directory      (const char* name, FILE* fp);
DLL_CHARACTERSTICS* check_memory_protection      (unsigned short val, DLL_CHARACTERSTICS* DllChars);

#endif