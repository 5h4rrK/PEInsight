// #include "parser.h"
#include "parser.h"
#include "pe_struct.h"
#include "pe_helper.h"
#include "print_template.h"

global int  MACHINE_ARCH_32 =0;
global int  MACHINE_ARCH_64 =0;
global long peaddress;  
global long NoOfSections;
global u64  importAddress;

struct SECTION_LINK* seclink;
static struct SECTION_LINK* head;

#define ORDINAL_FLAG_BIT    0x00000001
#define PATH "dump_dir/"
#define IMG_DATA_DIRECTORY(name, fp) read_data_directory(#name, fp)

DLL_CHARACTERSTICS* check_memory_protection(unsigned short val, DLL_CHARACTERSTICS* DllChars){
    if (((val ) & 0x00f0) == 0x40) {DllChars->IMAGE_DYNAMIC_BASE ="Enabled";}
    else {DllChars->IMAGE_DYNAMIC_BASE ="Disabled";}
    if (((val ) & 0x0f00) == 0x01){ DllChars->DATA_EXECUTION_PREVENTION = "Enabled";}
    else {DllChars->DATA_EXECUTION_PREVENTION = "Disabled";}
    if (((val ) & 0x0f00) == 0x04) {DllChars->STRUCTURED_EXCEPTION_HANDLER = "Disabled";}
    else {DllChars->STRUCTURED_EXCEPTION_HANDLER = "Enabled";}
    return DllChars;
}

void dump_section(FILE* fp, const IMAGE_SECTION_HEADER* section){
    char* fullPath = (char *) malloc(0xf + length(PATH));
    sprintf(fullPath, "%s%s", PATH, (char *) section->Name);
    printf("Dumping %s section into %s\n\t\t",section->Name ,fullPath);
    char* buffer = (char *) malloc(section->SizeOfRawData);
    long prevPointer = ftell(fp);
    fseek(fp, section->PointerToRawData, SEEK_SET);
    fread(buffer,1, section->SizeOfRawData, fp);
    FILE* fw = fopen(fullPath, "wb");
    fwrite(buffer, 1, section->SizeOfRawData, fw);
    fseek(fp, prevPointer, SEEK_SET);
}


static inline void read_data_directory(const char* name, FILE* fp) {
    IMAGE_DATA_DIRECTORY dir;
    dir.VirtualAddress = readLittleInt32(fp);
    dir.Size = readLittleInt32(fp);

    if (name == (char *) "IMPORT" && dir.Size > 0) importAddress = dir.VirtualAddress;
    printf("%-40s | 0x%-20x| 0x%-20x\n", name, dir.VirtualAddress, dir.Size);
}

void 
parse_dos_stub(FILE* fp){
    size_t stub_len = (size_t) (peaddress - ftell(fp) -1);
    unsigned char* dostub = (unsigned char*) malloc(stub_len);
    if(fread(dostub, 1, stub_len,  fp) == stub_len){
        printf("Dos Stub : ");
        for(int i=0; i< stub_len; i++){
            printf("%.2x ", *(dostub+i)); }
    }
    printf("\n");
    free(dostub);
    fseek(fp, peaddress, SEEK_SET);
}

// void 
// machine_arch(FILE* fp){
//     skip(fp, 0x04);
//     u16 status = readLittleInt16(fp);
//     switch(status) {
//         case IMAGE_FILE_MACHINE_AM33:
//         case IMAGE_FILE_MACHINE_ARM:
//         case IMAGE_FILE_MACHINE_I386:
//         case IMAGE_FILE_MACHINE_LOONGARCH32:
//         case IMAGE_FILE_MACHINE_M32R:
//         case IMAGE_FILE_MACHINE_MIPS16:
//         case IMAGE_FILE_MACHINE_MIPSFPU:
//         case IMAGE_FILE_MACHINE_MIPSFPU16:
//         case IMAGE_FILE_MACHINE_POWERPC:
//         case IMAGE_FILE_MACHINE_POWERPCFP:
//         case IMAGE_FILE_MACHINE_R4000:
//         case IMAGE_FILE_MACHINE_RISCV32:
//         case IMAGE_FILE_MACHINE_SH3:
//         case IMAGE_FILE_MACHINE_SH3DSP:
//         case IMAGE_FILE_MACHINE_SH4:
//         case IMAGE_FILE_MACHINE_THUMB:
//         case IMAGE_FILE_MACHINE_WCEMIPSV2:
//             MACHINE_ARCH_32 =  0x32; // 32-bit machine
//         default:
//             MACHINE_ARCH_64 =  0x64;
//         skip(fp, -6);
//     }
// }

void 
parse_dosheader(FILE *fp){
    IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*) malloc(sizeof(IMAGE_DOS_HEADER));
    dosheader->e_magic               = readLittleInt16(fp);
    dosheader->e_cblp                = readLittleInt16(fp);
    dosheader->e_cp                  = readLittleInt16(fp);
    dosheader->e_crlc                = readLittleInt16(fp);
    dosheader->e_cparhdr             = readLittleInt16(fp);
    dosheader->e_minalloc            = readLittleInt16(fp);
    dosheader->e_maxalloc            = readLittleInt16(fp);
    dosheader->e_ss                  = readLittleInt16(fp);
    dosheader->e_sp                  = readLittleInt16(fp);
    dosheader->e_csum                = readLittleInt16(fp);
    dosheader->e_ip                  = readLittleInt16(fp);
    dosheader->e_cs                  = readLittleInt16(fp);
    dosheader->e_lfarlc              = readLittleInt16(fp);
    dosheader->e_ovno                = readLittleInt16(fp);
    // Reserved Bytes skipping
    skip(fp, sizeof(u16) * 4);
    dosheader->e_oemid               = readLittleInt16(fp);
    dosheader->e_oeminfo             = readLittleInt16(fp);
    // Reserved Bytes skipping
    skip(fp, sizeof(u16) * 10);
    dosheader->e_lfanew              =  readLittleInt32(fp);
    peaddress = dosheader->e_lfanew;
    print_dos_headers(dosheader);
}

void 
parse_nt_headers(FILE* fp){
        NT_HEADER* ntheaders = (NT_HEADER*) malloc(sizeof(NT_HEADER));
        ntheaders->Signature                                            = readLittleInt32(fp);
        ntheaders->FileHeader.Machine                                   = readLittleInt16(fp);
        ntheaders->FileHeader.NumberOfSections                          = readLittleInt16(fp);
        ntheaders->FileHeader.TimeDateStamp                             = readLittleInt32(fp);
        ntheaders->FileHeader.PointerToSymbolTable                      = readLittleInt32(fp);
        ntheaders->FileHeader.NumberOfSymbols                           = readLittleInt32(fp);
        ntheaders->FileHeader.SizeOfOptionalHeader                      = readLittleInt16(fp);
        ntheaders->FileHeader.Characteristics                           = readLittleInt16(fp);
        ntheaders->OptionalHeader.Magic                                 = readLittleInt16(fp);
        ntheaders->OptionalHeader.MajorLinkerVersion                    = readLittleInt8(fp);
        ntheaders->OptionalHeader.MinorLinkerVersion                    = readLittleInt8(fp);
        ntheaders->OptionalHeader.SizeOfCode                            = readLittleInt32(fp);
        ntheaders->OptionalHeader.SizeOfInitializedData                 = readLittleInt32(fp);
        ntheaders->OptionalHeader.SizeOfUninitializedData               = readLittleInt32(fp);
        ntheaders->OptionalHeader.AddressOfEntryPoint                   = readLittleInt32(fp);
        ntheaders->OptionalHeader.BaseOfCode                            = readLittleInt32(fp);
        if(ntheaders->OptionalHeader.Magic == 0x10B){
            MACHINE_ARCH_32 = 1;
            ntheaders->OptionalHeader.BaseOfData                        = readLittleInt32(fp);
            ntheaders->OptionalHeader.Base.ImageBaseAddress32           = readLittleInt32(fp);
        }
        else if(ntheaders->OptionalHeader.Magic == 0x20B){
            MACHINE_ARCH_64 = 1;
            ntheaders->OptionalHeader.Base.ImageBaseAddress64           = readLittleInt64(fp);
        }
        ntheaders->OptionalHeader.SectionAlignment                      = readLittleInt32(fp);
        ntheaders->OptionalHeader.FileAlignment                         = readLittleInt32(fp);
        ntheaders->OptionalHeader.MajorOperatingSystemVersion           = readLittleInt16(fp);
        ntheaders->OptionalHeader.MinorOperatingSystemVersion           = readLittleInt16(fp);
        ntheaders->OptionalHeader.MajorImageVersion                     = readLittleInt16(fp);
        ntheaders->OptionalHeader.MinorImageVersion                     = readLittleInt16(fp);
        ntheaders->OptionalHeader.MajorSubsystemVersion                 = readLittleInt16(fp);
        ntheaders->OptionalHeader.MinorSubsystemVersion                 = readLittleInt16(fp);
        ntheaders->OptionalHeader.Win32VersionValue                     = readLittleInt32(fp);
        ntheaders->OptionalHeader.SizeOfImage                           = readLittleInt32(fp);
        ntheaders->OptionalHeader.SizeOfHeaders                         = readLittleInt32(fp);
        ntheaders->OptionalHeader.CheckSum                              = readLittleInt32(fp);
        ntheaders->OptionalHeader.Subsystem                             = readLittleInt16(fp);
        ntheaders->OptionalHeader.DllCharacteristics                    = readLittleInt16(fp);
        if(ntheaders->OptionalHeader.Magic == 0x10B){
            ntheaders->OptionalHeader.StackHeap.SizeOfStackReserve32    = readLittleInt32(fp);
            ntheaders->OptionalHeader.StackHeap.SizeOfStackCommit32     = readLittleInt32(fp);
            ntheaders->OptionalHeader.StackHeap.SizeOfHeapReserve32     = readLittleInt32(fp);
            ntheaders->OptionalHeader.StackHeap.SizeOfHeapCommit32      = readLittleInt32(fp);
        }
        else if(ntheaders->OptionalHeader.Magic == 0x20B){
            ntheaders->OptionalHeader.StackHeap.SizeOfStackReserve64    = readLittleInt64(fp);
            ntheaders->OptionalHeader.StackHeap.SizeOfStackCommit64     = readLittleInt64(fp);
            ntheaders->OptionalHeader.StackHeap.SizeOfHeapReserve64     = readLittleInt64(fp);
            ntheaders->OptionalHeader.StackHeap.SizeOfHeapCommit64      = readLittleInt64(fp);
        }
        ntheaders->OptionalHeader.LoaderFlags                           = readLittleInt32(fp);
        ntheaders->OptionalHeader.NumberOfRvaAndSizes                   = readLittleInt32(fp);
        DLL_CHARACTERSTICS* DllChars = (DLL_CHARACTERSTICS*) malloc(sizeof(DLL_CHARACTERSTICS));
        check_memory_protection(ntheaders->OptionalHeader.DllCharacteristics, DllChars);
        print_nt_headers(ntheaders, DllChars);
        NoOfSections = ntheaders->FileHeader.NumberOfSections;
        free(ntheaders);
        free(DllChars);
        printf("%-40s | %-20s  | %-20s\n", "DIRECTORY_NAME", "VirtualAddress", "Size");
        IMG_DATA_DIRECTORY(EXPORT, fp);
        IMG_DATA_DIRECTORY(IMPORT, fp);
        IMG_DATA_DIRECTORY(RESOURCE, fp);
        IMG_DATA_DIRECTORY(EXCEPTION, fp);
        IMG_DATA_DIRECTORY(SECURITY, fp);
        IMG_DATA_DIRECTORY(BASE_REALLOCATION_TABLE, fp);
        IMG_DATA_DIRECTORY(DEBUG_DIRECTORY, fp);
        IMG_DATA_DIRECTORY(COPYRIGHT_ARCH_SP_DATA, fp);
        IMG_DATA_DIRECTORY(GLOBAL_PTR, fp);
        IMG_DATA_DIRECTORY(TLS_DIRECTORY, fp);
        IMG_DATA_DIRECTORY(LOAD_CONFIG_DATA, fp);
        IMG_DATA_DIRECTORY(BOUND_IMPORT_DIR, fp);
        IMG_DATA_DIRECTORY(IMPORT_ADDRESS_TABLE, fp);
        IMG_DATA_DIRECTORY(DELAY_LOAD_IMPORT_DESC, fp);
        IMG_DATA_DIRECTORY(COM_RUNTIME_DESC, fp);
        IMG_DATA_DIRECTORY(RESERVED, fp);
}

void 
copy_attributes(const IMAGE_SECTION_HEADER* section_headers,struct SECTION_LINK* seclink){
    for( int i=0; i<8; i++){
        seclink->Name[i] = section_headers->Name[i];
        }
    seclink->VirtualAddress =  section_headers->VirtualAddress;
    seclink->SizeofRawData =  section_headers->SizeOfRawData;
    seclink->PointerToRawData =  section_headers->PointerToRawData;
    struct SECTION_LINK* newNode = malloc(sizeof(struct SECTION_LINK));   
    seclink->next = newNode;

}

void 
traverse_link(struct SECTION_LINK* templink){
    while(templink->next != NULL){
        printf("%20s %10d\n", templink->Name, templink->VirtualAddress);
        templink = templink->next;
    }
}

void 
parse_section_headers(FILE *fp){
    seclink = (struct SECTION_LINK*) malloc(sizeof(struct SECTION_LINK));
    head = seclink;
    for(int i=0; i<NoOfSections; i++){
            IMAGE_SECTION_HEADER* section_headers = (IMAGE_SECTION_HEADER*) malloc(sizeof(IMAGE_SECTION_HEADER));
            for( int i=0; i<8; i++){
            section_headers->Name[i]                  = readLittleInt8(fp);
                }
            section_headers->Misc.PhysicalAddress     = readLittleInt32(fp);
            section_headers->Misc.VirtualSize         = section_headers->Misc.PhysicalAddress;
            section_headers->VirtualAddress           = readLittleInt32(fp);       
            section_headers->SizeOfRawData            = readLittleInt32(fp);       
            section_headers->PointerToRawData         = readLittleInt32(fp);       
            section_headers->PointerToRelocations     = readLittleInt32(fp);       
            section_headers->PointerToLinenumbers     = readLittleInt32(fp);       
            section_headers->NumberOfRelocations      = readLittleInt16(fp);       
            section_headers->NumberOfLinenumbers      = readLittleInt16(fp);       
            section_headers->Characteristics          = readLittleInt32(fp);    
            print_section_headers(section_headers);
            copy_attributes(section_headers, seclink);
            seclink = seclink->next;
            dump_section(fp, section_headers);
            free(section_headers);
    }
}

struct RetResult{
    u64 file_of_address;
    unsigned char section_name[8];
};

struct RetResult*
file_offset_name_address(u64 virtualAddress){
    // int count=0;
    struct RetResult* res = (struct RetResult *) malloc(sizeof(struct RetResult));
    struct SECTION_LINK* temp = head;
    while(temp != NULL || temp != 0){
        if (virtualAddress < (temp->VirtualAddress + temp->SizeofRawData)){
            // u64 res =(temp->PointerToRawData + (temp->VirtualAddress - importAddress));
            // printf("<< %x | %s  %x  %x %x  = %d >> \n\n", virtualAddress ,temp->Name, temp->VirtualAddress, temp->SizeofRawData, temp->PointerToRawData, ;
            res->file_of_address = (temp->PointerToRawData + abs( (long)temp->VirtualAddress, (long)virtualAddress));
            for(int i=0; i< 8; i++){
                res->section_name[i] = temp->Name[i];
            }
            return res;
        }
        temp = temp->next;
        // count++;
    }
    res->file_of_address=INVALID_ADDRESS;
    return res;
}

u64
file_offset_address(u64 virtualAddress){
    struct SECTION_LINK* temp = head;
    while(temp != NULL || temp != 0){
            if (virtualAddress < (temp->VirtualAddress + temp->SizeofRawData)){
                return (temp->PointerToRawData + abs( (long)temp->VirtualAddress, (long)virtualAddress));
            }
            temp = temp->next;
        }
        return INVALID_ADDRESS;
}

void
copy_result_fields(const struct RetResult* result, IMPORT_DESCRIPTOR* import_descriptors, unsigned char val){
    if(val == '\x00'){
        import_descriptors->OriginalFirstThunk_FOA =  result->file_of_address;
        for(int i=0; i < IMAGE_SIZEOF_SHORT_NAME; i++) import_descriptors->OriginalFirstThunk_SECTION_NAME[i] = result->section_name[i];
    }
    else if(val == '\x01'){
        import_descriptors->Name_FOA =  result->file_of_address;
        for(int i=0; i < IMAGE_SIZEOF_SHORT_NAME; i++) import_descriptors->Name_FOA_SECTION_NAME[i] = result->section_name[i];
    }
    else if(val == '\x02'){
        import_descriptors->FirstThunk_FOA =  result->file_of_address;
        for(int i=0; i < IMAGE_SIZEOF_SHORT_NAME; i++) import_descriptors->FirstThunk_FOA_SECTION_NAME[i] = result->section_name[i];
    }
}

void
parse_dll_name(FILE* fp){
    char dllname[DLL_NAME_MAX_SIZE];
    int i=0;
    while(i <DLL_NAME_MAX_SIZE){
        dllname[i] = (char) fgetc(fp);
        if (dllname[i]== 0){
            break; //? Instead consume till padding of 4 bytes 
        }
        i++;
    }
    printf("\n\t%s\n\t----------------\n", dllname);
}

void 
parse_lookup_table(FILE* fp){
    u64 addr;
    printf("\t  %-10s   %-64s |\n", "Hint", "Name");
    printf("\t%50s\n","+-------------------------------------------------------------------------------+");
    while (1){   
        if (MACHINE_ARCH_32){ 
                addr = readLittleInt32(fp); 
            }
        else if (MACHINE_ARCH_64){ 
            addr = readLittleInt64(fp); 
            }

        long ilt_address = ftell(fp);
        if(addr == 0) break;

        u64 foa = file_offset_address(addr);
        if (foa == INVALID_ADDRESS){continue; }
        // printf("Function Names are at %x\n\n",foa);
        // ? Parse the address and read the function names 
        fseek(fp, foa, SEEK_SET);
        IMPORT_BY_NAME* importNames = (IMPORT_BY_NAME*) malloc(sizeof(IMPORT_BY_NAME));
        //? Ordinal Flag (1 bit , 31st bit), Ordinal Number (0-15) , Hint (0 - 30 )


        // printf("ILT %x , Current FOA %x , Current  %x\n",prev_pos,foa ,ftell(fp));
        importNames->HintValue = readLittleInt16(fp);

        for(int i=0; i< FUNCTION_NAME_MAX_SIZE; i++){
            importNames->FunctionName[i] = (char) fgetc(fp);
            if(importNames->FunctionName[i] == '\x00') break;
        }
        printf("\t| %-10d | %-64s |\n",importNames->HintValue, importNames->FunctionName);

        fseek(fp, ilt_address, SEEK_SET);
        free(importNames);
    }
    printf("\t%50s\n","+-------------------------------------------------------------------------------+");

}

static inline int 
is_end_of_import_descriptor(IMPORT_DESCRIPTOR* import_descriptors){
    if( import_descriptors->Characterstics == 0 &&\
        import_descriptors->OriginalFirstThunk==0 &&\
        import_descriptors->TimeDateStamp==0 &&\
        import_descriptors->ForwarderChain==0 &&\
        import_descriptors->Name==0 &&\
        import_descriptors->FirstThunk==0 ) return 1;
    else return 0;
}

void
parse_import_descriptors(FILE* fp){
    while(1){
        IMPORT_DESCRIPTOR* import_descriptors = (IMPORT_DESCRIPTOR *) malloc(sizeof(IMPORT_DESCRIPTOR));
        import_descriptors->Characterstics              = readLittleInt32(fp);
        import_descriptors->OriginalFirstThunk          = import_descriptors->Characterstics;
        import_descriptors->TimeDateStamp               = readLittleInt32(fp);
        import_descriptors->ForwarderChain              = readLittleInt32(fp);
        import_descriptors->Name                        = readLittleInt32(fp);
        import_descriptors->FirstThunk                  = readLittleInt32(fp);
        
        if (is_end_of_import_descriptor(import_descriptors)) break;
        //? Translate the virtual address to file offset address 

        struct RetResult* result = (struct RetResult *) malloc(sizeof(struct RetResult));
        result = file_offset_name_address(import_descriptors->OriginalFirstThunk);
        copy_result_fields(result, import_descriptors, 0x0);

        result = file_offset_name_address(import_descriptors->Name);
        copy_result_fields(result, import_descriptors, 0x1);

        result = file_offset_name_address(import_descriptors->FirstThunk);
        copy_result_fields(result, import_descriptors, 0x2);
        
        // printf("The address of file is :: %x %d %s\n\n", import_descriptors->OriginalFirstThunk_FOA, import_descriptors->OriginalFirstThunk_FOA, import_descriptors->OriginalFirstThunk_SECTION_NAME);

        // printf("The address of file is :: %x %d %s\n\n", import_descriptors->Name_FOA, import_descriptors->Name_FOA, import_descriptors->Name_FOA_SECTION_NAME);

        long int prev_pos = ftell(fp);
        fseek(fp, (long) import_descriptors->Name_FOA, SEEK_SET);
        parse_dll_name(fp);
        fseek(fp, prev_pos, SEEK_SET);

        // printf("The address of file is :: %x %d %s\n\n", import_descriptors->FirstThunk_FOA, import_descriptors->FirstThunk_FOA, import_descriptors->FirstThunk_FOA_SECTION_NAME);

        prev_pos = ftell(fp);
        fseek(fp, (long) import_descriptors->FirstThunk_FOA, SEEK_SET);
        parse_lookup_table(fp);
        fseek(fp, prev_pos, SEEK_SET);
        free(result);
        free(import_descriptors);
    }
}


void 
locate_import_lookup_table(FILE* fp){
    struct RetResult* result = file_offset_name_address(importAddress);
    printf("Import Data Array Directory references -----> %x --> %s\n", result->file_of_address, result->section_name);
    long prevAddress = ftell(fp);
    fseek(fp, result->file_of_address, SEEK_SET);
    parse_import_descriptors(fp);
    fseek(fp, prevAddress, SEEK_SET);

}

void 
parse_structure(FILE* fp){
    parse_dosheader(fp);
    parse_dos_stub(fp);
    // machine_arch(fp);
    parse_nt_headers(fp);
    parse_section_headers(fp);
    locate_import_lookup_table(fp);

}