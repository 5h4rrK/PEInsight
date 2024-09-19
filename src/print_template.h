#if !(defined(_PARSER_H))
#include "pe_helper.h"
#endif 

void
print_dos_headers(const IMAGE_DOS_HEADER* dosheader){
    printf("+-------------------------------------------------------------------+\n");
    print_mem("DosHeader Magic"        , dosheader->e_magic);
    print_mem("DosHeader BytesOnLastPage", dosheader->e_cblp);
    print_mem("DosHeader PagesInFile  ", dosheader->e_cp);
    print_mem("DosHeader Relocations  ", dosheader->e_crlc);
    print_mem("DosHeader SizeOfHdr    ", dosheader->e_cparhdr);
    print_mem("DosHeader MinAlloc     ", dosheader->e_minalloc);
    print_mem("DosHeader MaxAlloc     ", dosheader->e_maxalloc);
    print_mem("DosHeader InitialSS    ", dosheader->e_ss);
    print_mem("DosHeader InitialSP    ", dosheader->e_sp);
    print_mem("DosHeader Checksum     ", dosheader->e_csum);
    print_mem("DosHeader InitialIP    ", dosheader->e_ip);
    print_mem("DosHeader InitialCS    ", dosheader->e_cs);
    print_mem("DosHeader RelocAddr    ", dosheader->e_lfarlc);
    print_mem("DosHeader OverlayNum   ", dosheader->e_ovno);
    print_mem("DosHeader Reserved     ", *dosheader->e_res);
    print_mem("DosHeader OEMID        ", dosheader->e_oemid);
    print_mem("DosHeader OEMInfo      ", dosheader->e_oeminfo);
    print_mem("DosHeader Reserved2    ", *dosheader->e_res2);
    print_mem("DosHeader PEAddress    ", dosheader->e_lfanew);
    printf("+-------------------------------------------------------------------+\n");
}

void 
print_nt_headers(const NT_HEADER* ntheaders, const DLL_CHARACTERSTICS* DllChars){
    printf("+-------------------------------------------------------------------+\n");
    print_mem("NtHeader Signature", ntheaders->Signature);
    print_mem("  FileHeader Machine", ntheaders->FileHeader.Machine);
    print_mem("  FileHeader NumberOfSections", ntheaders->FileHeader.NumberOfSections);
    print_mem("  FileHeader TimeDateStamp", ntheaders->FileHeader.TimeDateStamp);
    print_mem("  FileHeader PointerToSymbolTable", ntheaders->FileHeader.PointerToSymbolTable);
    print_mem("  FileHeader NumberOfSymbols", ntheaders->FileHeader.NumberOfSymbols);
    print_mem("  FileHeader SizeOfOptionalHeader", ntheaders->FileHeader.SizeOfOptionalHeader);
    print_mem("  FileHeader Characteristics", ntheaders->FileHeader.Characteristics);

    print_mem("    OptionalHeader Magic", ntheaders->OptionalHeader.Magic);
    print_mem("    OptionalHeader MajorLinkerVersion", ntheaders->OptionalHeader.MajorLinkerVersion);
    print_mem("    OptionalHeader MinorLinkerVersion", ntheaders->OptionalHeader.MinorLinkerVersion);
    print_mem("    OptionalHeader SizeOfCode", ntheaders->OptionalHeader.SizeOfCode);
    print_mem("    OptionalHeader SizeOfInitializedData", ntheaders->OptionalHeader.SizeOfInitializedData);
    print_mem("    OptionalHeader SizeOfUninitializedData", ntheaders->OptionalHeader.SizeOfUninitializedData);
    print_mem("    OptionalHeader AddressOfEntryPoint", ntheaders->OptionalHeader.AddressOfEntryPoint);
    print_mem("    OptionalHeader BaseOfCode", ntheaders->OptionalHeader.BaseOfCode);
    if(ntheaders->OptionalHeader.Magic == 0x10B){
    print_mem("    OptionalHeader BaseOfData", ntheaders->OptionalHeader.BaseOfData);
    print_mem("    OptionalHeader ImageBase", ntheaders->OptionalHeader.Base.ImageBaseAddress32);
    }
    else if(ntheaders->OptionalHeader.Magic == 0x20B){
    print_mem("    OptionalHeader ImageBase", ntheaders->OptionalHeader.Base.ImageBaseAddress64);
    }
    print_mem("    OptionalHeader SectionAlignment", ntheaders->OptionalHeader.SectionAlignment);
    print_mem("    OptionalHeader FileAlignment", ntheaders->OptionalHeader.FileAlignment);
    print_mem("    OptionalHeader MajorOperatingSystemVersion", ntheaders->OptionalHeader.MajorOperatingSystemVersion);
    print_mem("    OptionalHeader MinorOperatingSystemVersion", ntheaders->OptionalHeader.MinorOperatingSystemVersion);
    print_mem("    OptionalHeader MajorImageVersion", ntheaders->OptionalHeader.MajorImageVersion);
    print_mem("    OptionalHeader MinorImageVersion", ntheaders->OptionalHeader.MinorImageVersion);
    print_mem("    OptionalHeader MajorSubsystemVersion", ntheaders->OptionalHeader.MajorSubsystemVersion);
    print_mem("    OptionalHeader MinorSubsystemVersion", ntheaders->OptionalHeader.MinorSubsystemVersion);
    print_mem("    OptionalHeader Win32VersionValue", ntheaders->OptionalHeader.Win32VersionValue);
    print_mem("    OptionalHeader SizeOfImage", ntheaders->OptionalHeader.SizeOfImage);
    print_mem("    OptionalHeader SizeOfHeaders", ntheaders->OptionalHeader.SizeOfHeaders);
    print_mem("    OptionalHeader CheckSum", ntheaders->OptionalHeader.CheckSum);
    print_mem("    OptionalHeader Subsystem", ntheaders->OptionalHeader.Subsystem);
    print_mem("    OptionalHeader DllCharacteristics", ntheaders->OptionalHeader.DllCharacteristics);
    print_str("                   ASLR ", DllChars->IMAGE_DYNAMIC_BASE);
    print_str("                   DEP", DllChars->DATA_EXECUTION_PREVENTION);
    print_str("                   NO SEH", DllChars->STRUCTURED_EXCEPTION_HANDLER);
    if(ntheaders->OptionalHeader.Magic == 0x10B){
    print_mem("    OptionalHeader SizeOfStackReserve", ntheaders->OptionalHeader.StackHeap.SizeOfStackReserve32);
    print_mem("    OptionalHeader SizeOfStackCommit", ntheaders->OptionalHeader.StackHeap.SizeOfStackCommit32);
    print_mem("    OptionalHeader SizeOfHeapReserve", ntheaders->OptionalHeader.StackHeap.SizeOfHeapReserve32);
    print_mem("    OptionalHeader SizeOfHeapCommit", ntheaders->OptionalHeader.StackHeap.SizeOfHeapCommit32);
    }
    else if(ntheaders->OptionalHeader.Magic == 0x20B){
    print_mem("    OptionalHeader SizeOfStackReserve", ntheaders->OptionalHeader.StackHeap.SizeOfStackReserve32);
    print_mem("    OptionalHeader SizeOfStackCommit", ntheaders->OptionalHeader.StackHeap.SizeOfStackCommit32);
    print_mem("    OptionalHeader SizeOfHeapReserve", ntheaders->OptionalHeader.StackHeap.SizeOfHeapReserve32);
    print_mem("    OptionalHeader SizeOfHeapCommit", ntheaders->OptionalHeader.StackHeap.SizeOfHeapCommit32);
    }
    print_mem("    OptionalHeader LoaderFlags", ntheaders->OptionalHeader.LoaderFlags);
    print_mem("    OptionalHeader NumberOfRvaAndSizes", ntheaders->OptionalHeader.NumberOfRvaAndSizes);
    printf("+-------------------------------------------------------------------+\n");

}

void 
print_section_headers(const IMAGE_SECTION_HEADER* section_headers){
    printf("\n\t\t\tSectionName :: %s\n\t\t-------------------------------\n", section_headers->Name);
    printf("\t\t|%-50s  |  %-11s |\n\t\t","Name ",section_headers->Name);
    print_mem_fmt("PhysicalAddress ",section_headers->Misc.PhysicalAddress);
    print_mem_fmt("VirtualSize ", section_headers->Misc.VirtualSize);
    print_mem_fmt("VirtualAddress ", section_headers->VirtualAddress);
    print_mem_fmt("SizeofRawData", section_headers->SizeOfRawData);
    print_mem_fmt("PointerToRawData", section_headers->PointerToRawData);
    print_mem_fmt("PointerToRelocations", section_headers->PointerToRelocations);
    print_mem_fmt("PointerToLinenumbers", section_headers->PointerToLinenumbers);
    print_mem_fmt("NumberOfRelocations", section_headers->NumberOfRelocations);
    print_mem_fmt("Characteristics", section_headers->Characteristics);

}