/**Eventual Additions
 * --------------------------------------------
 *  1. Add OP and PROC to both program and section headers under optional inclusion field at end of row with no header that doesn't show up normally.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

// Structs
typedef struct {
    Elf64_Shdr header;
    unsigned char *bytes;
    int found;
} LoadedSection;

typedef struct {
    uint64_t address;
    unsigned char bytes[16];
    size_t length;
    char mnemonic[32];
    char operands[96];
} Instruction;

typedef struct {
    unsigned char legacy[4];
    int legacy_count;

    int has_rex;
    unsigned char rex;
    int rexW;
    int rexR;
    int rexX;
    int rexB;

    int operand_size_override;  // 0x66
    int address_size_override;  // 0x67
    int lock;   // F0
    int repne;  // F2
    int rep;    // F3
} PrefixState;

typedef struct {
    uint8_t mod;
    uint8_t reg;
    uint8_t rm;
} ModRM;

// Color Definition
    // normal
#define C_RED           "\x1b[38;5;196m"
#define C_ORANGE        "\x1b[38;5;202m"
#define C_YELLOW        "\x1b[38;5;226m"
#define C_GREEN         "\x1b[38;5;46m"
#define C_CYAN          "\x1b[38;5;51m"
#define C_BLUE          "\x1b[38;5;21m"
#define C_PURPLE        "\x1b[38;5;201m"
    // reset
#define C_RESET         "\x1b[0m"

// Function prototypes
void printBanner();
void printBorder();
// EHDR
void printEhdr(Elf64_Ehdr*, FILE*);              
void printEhdrInfo(Elf64_Ehdr);
// PHDR
void printPhdrs(Elf64_Ehdr, FILE*, Elf64_Phdr*);                     
void printPhdrInfo(Elf64_Phdr);
// SHDR
char *getShStrTab(Elf64_Ehdr, FILE*);
void printShdrs(Elf64_Ehdr, FILE*, Elf64_Shdr*, char*);                     
void printShdrInfo(Elf64_Shdr, const char*);
// SYMTAB
void printSymtab(Elf64_Shdr*, Elf64_Ehdr, FILE*);
void printSymtabInfo(Elf64_Sym, const char*);
// DECODING
LoadedSection loadSectionByName(Elf64_Ehdr, Elf64_Shdr*, FILE*, char*, const char*);
void decodeTextSection(const unsigned char*, size_t, uint64_t);
void disassembleSection(Elf64_Ehdr, Elf64_Shdr*, FILE*, char*);
size_t decodeInstruction(const unsigned char*, size_t, uint64_t, Instruction*);

//  Decoding helpers
int isPrefix(unsigned char);
size_t parsePrefixes(const unsigned char*, size_t, PrefixState*);
int parseOpcode (const unsigned char*, size_t, PrefixState*, Instruction*, size_t);
int parseModRM (const unsigned char*, size_t, ModRM*, PrefixState*, Instruction*, size_t);
const char* getRegisterLegacy(uint8_t, uint8_t);
const char* getRegisterREX(uint8_t, uint8_t);
const char* detExtension(ModRM);

// HELPERS
const char *getSectionTypeName(uint32_t);
const char *getProgramTypeName(uint32_t);

// ASCII art
const char *title[] = 
    {C_ORANGE "\n:::::::::  :::::::::      :::     ::::    ::: ::::::::: ::::::::::: ::::::::  ",
                ":+:    :+: :+:    :+:   :+: :+:   :+:+:   :+: :+:    :+:    :+:    :+:    :+: ",
                "+:+    +:+ +:+    +:+  +:+   +:+  :+:+:+  +:+ +:+    +:+    +:+    +:+         ",     
                "+#++:++#+  +#++:++#:  +#++:++#++: +#+ +:+ +#+ +#+    +:+    +#+    +#++:++#++  ",
                "+#+    +#+ +#+    +#+ +#+     +#+ +#+  +#+#+# +#+    +#+    +#+           +#+  ",
                "#+#    #+# #+#    #+# #+#     #+# #+#   #+#+# #+#    #+#    #+#    #+#    #+# ", 
                "#########  ###    ### ###     ### ###    #### ######### ########### ########   " C_RESET};  

// lookup tables
const char *OSABI_Values[] = {"No extensions or unspecified", "Hewlett-Packard HP-UX", "NetBSD", "GNU", 
        "Linux", "Sun Solaris", "AIX", "IRIX", "FreeBSD", "Compaq TRU64 UNIX", "Novell Modesto", 
        "Open BSD", "Open VMS", "Hewlett-Packard Non-Stop Kernel", "Amiga Research OS", "Amiga Research OS", 
        "The FenixOS highly scalable multi-core OS", "Nuxi CloudABI", "Stratus Technologies OpenVOS", 
        "Architecture-specific"};

const char *pFlag_Values[] = {"---", "--\x1b[38;5;196mX"C_RESET, "-W-", "-W\x1b[38;5;196mX"C_RESET, "R--", "R-\x1b[38;5;196mX"C_RESET, "RW-", "RW\x1b[38;5;196mX"C_RESET};

const char *sFlag_Values1[] = {"---", "W--", "-A-", "WA-", "--\x1b[38;5;196mX"C_RESET, "W-\x1b[38;5;196mX"C_RESET, "-A\x1b[38;5;196mX"C_RESET, "WA\x1b[38;5;196mX"C_RESET};
const char *sFlag_Values2[] = {"----", "M---", "-S--", "MS--", "--I-", "M-I-", "-SI-", "MSI-", "---L",
        "M--L", "-S-L", "MS-L", "--IL", "M-IL", "-SIL", "MSIL"};
const char *sFlag_Values3[] = {"----", "O---", "-G--", "OG--", "--T-", "O-T-", "-GT-", "OGT-", "---C" ,
        "O--C", "-G-C", "OG-C", "--TC", "O-TC", "-GTC", "OGTC"};

// 8-Bit Register tables
const char *bit16[] = { "ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di"  };
const char *bit32[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
const char *bit64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" };

// REX Register tables
const char *rex16[] = {"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
const char *rex32[] = {"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
const char *rex64[] = {"r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};

int main() {
    // Banner and title
    printBanner();
    printf("\nBrandon's ELF Disassembler Tool\n");
    printBorder();

    FILE *file = fopen("add.o", "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }
    Elf64_Ehdr header;

    //  ELF HEADER
    printEhdr(&header, file);

    //  PROGRAM HEADERS 
    Elf64_Phdr *pheaders = malloc(header.e_phnum * sizeof(Elf64_Phdr));
    printPhdrs(header, file, pheaders);

    //  SECTION HEADERS
    Elf64_Shdr *sheaders = malloc(header.e_shnum * sizeof(Elf64_Shdr));
    char *shstrtab = getShStrTab(header, file);
    if (!shstrtab) {
        printf("Failed to load String Table");
        free(pheaders);
        free(sheaders);
        fclose(file);
        return 1;
    }
    printShdrs(header, file, sheaders, shstrtab);

    //  SYMBOL TABLE
    printSymtab(sheaders, header, file);

    //  DECODING
    disassembleSection(header, sheaders, file, shstrtab);

    free(pheaders);
    free(sheaders);
    free(shstrtab);
    fclose(file);
}

void printBanner() {
    for (int i = 0; i < 7; i++) {
        printf("%s\n", title[i]);
    }
}

void printBorder() {
    printf("\n———————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————\n");
}

const char *getSectionTypeName(uint32_t type) {
    switch (type) {
        case SHT_NULL: return "SHT_NULL";
        case SHT_PROGBITS: return "SHT_PROGBITS";
        case SHT_SYMTAB: return "SHT_SYMTAB";
        case SHT_STRTAB: return "SHT_STRTAB";
        case SHT_RELA: return "SHT_RELA";
        case SHT_HASH: return "SHT_HASH";
        case SHT_DYNAMIC: return "SHT_DYNAMIC";
        case SHT_NOTE: return "SHT_NOTE";
        case SHT_NOBITS: return "SHT_NOBITS";
        case SHT_REL: return "SHT_REL";
        case SHT_SHLIB: return "SHT_SHLIB";
        case SHT_DYNSYM: return "SHT_DYNSYM";
        case SHT_INIT_ARRAY: return "SHT_INIT_ARRAY";
        case SHT_FINI_ARRAY: return "SHT_FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "SHT_PREINIT_ARRAY";
        case SHT_GROUP: return "SHT_GROUP";
        case SHT_SYMTAB_SHNDX: return "SHT_SYMTAB_SHNDX";
        default:
            if (type >= SHT_LOOS && type <= SHT_HIOS) return "OS Specific";
            if (type >= SHT_LOPROC && type <= SHT_HIPROC) return "Processor Specific";
            if (type >= SHT_LOUSER && type <= SHT_HIUSER) return "User Specific";
            return "UNKNOWN";
    }
}

const char *getProgramTypeName(uint32_t type) {
    switch (type) {
        case PT_NULL: return "NULL";
        case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE";
        case PT_SHLIB: return "SHLIB";
        case PT_PHDR: return "PHDR";
        case PT_TLS: return "TLS";
        default:
            if (type >= PT_LOOS && type <= PT_HIOS) return "OS Specific";
            if (type >= PT_LOPROC && type <= PT_HIPROC) return "Processor Specific";
            return "UNKNOWN";
    }
}

// HEADERS

void printEhdr(Elf64_Ehdr *EH, FILE* F) {
    fread(EH, sizeof(Elf64_Ehdr), 1, F);    //read ehdr
    printEhdrInfo(*EH);   
    printBorder();
}

void printEhdrInfo(Elf64_Ehdr h) {
    printf("%s\n\n", "ELF Header:");
    printf("Magic Number: \t\x1b[38;5;46m[%02X][%c][%c][%c]"C_RESET, h.e_ident[0], h.e_ident[1], h.e_ident[2], h.e_ident[3]);
    for(int i = 4; i < sizeof(h.e_ident); i++) {
        printf(" %02x", h.e_ident[i]);
    }

    //  headers
    printf("\n\n%-32s%-32s%s", "Field", "Value", "Raw Data");
    
    //  Architecture
    printf("\n%-32s", "Architecture:");
    if(h.e_ident[EI_CLASS] == 0) {
        printf("%-32s", "Invalid");
    } else if(h.e_ident[EI_CLASS] == 1) {
        printf("%-32s", "32-bit Objects");
    } else if(h.e_ident[EI_CLASS] == 2) {
        printf("%-32s", "64-bit Objects");
    } else {
        printf("%-32s", "Unknown");
    }
    printf("0x%02X", h.e_ident[EI_CLASS]);
    //  Data Encoding
    printf("\n%-32s", "Data Encoding:");
    if(h.e_ident[EI_DATA] == 0) {
        printf("%-32s", "Invalid");
    } else if(h.e_ident[EI_DATA] == 1) {
        printf("%-32s", "LSB (Little Endian)");
    } else if(h.e_ident[EI_DATA] == 2) {
        printf("%-32s", "MSB (Big Endian)");
    } else {
        printf("%-32s", "Unknown");
    }
    printf("0x%02X", h.e_ident[EI_DATA]);
    //  Version
    printf("\n%-32s", "File Version:");
    if(h.e_ident[EI_VERSION] == 0) {
        printf("%-32s", "Invalid");
    } else if(h.e_ident[EI_VERSION] == 1) {
        printf("%-32s", "Current");
    } else {
        printf("%-32s", "Unknown");
    }
    printf("0x%02X", h.e_ident[EI_VERSION]);
    //  OSABI:
    if (h.e_ident[EI_OSABI] < 20) {
        printf("\n%-32s%-32s0x%02X", "OS/ABI:", OSABI_Values[h.e_ident[EI_OSABI]], h.e_ident[EI_OSABI]);
    } else {
        printf("\n%-32s%-32s0x%02X", "OS/ABI:", "UNKNOWN", h.e_ident[EI_OSABI]);
    }
    //  ABI Version
    printf("\n%-32s%-32d0x%02X", "OS/ABI Version:", (int)(h.e_ident[EI_ABIVERSION]), h.e_ident[EI_ABIVERSION]);
    //  File Type
    printf("\n%-32s", "File Type:");
    if(h.e_type == 0) {
        printf("%-32s", "No File Type");
    } else if(h.e_type == 1) {
        printf("%-32s", "Relocatable File");
    } else if(h.e_type == 2) {
        printf("%-32s", "Executable File");
    } else if(h.e_type == 3) {
        printf("%-32s", "Shared Object File");
    } else if(h.e_type == 4) {
        printf("%-32s", "Core File");
    } else if(h.e_type == 0xFE00 || h.e_type == 0xfeff) {
        printf("%-32s", "OpSys-Specific");
    } else if(h.e_type == 0xff00 || h.e_type == 0xffff) {
        printf("%-32s", "Processor-Specific");
    } else {
        printf("%-32s", "Unknown");
    }
    printf("0x%02X", h.e_type);
    //  Architecture
    printf("\n%-32s%-32s0x%02X", "Architecture:", "See Appendix A", h.e_machine);
    //  Version
    printf("\n%-32s", "Version:");
    if(h.e_version == 0) {
        printf("%-32s", "Invalid");
    } else if(h.e_version == 1) {
        printf("%-32s", "Current");
    } else {
        printf("%-32s", "Unknown");
    }
    printf("0x%02X", h.e_version);
    //  Entry Address
    printf("\n\n%-32s[%05d] 0x%016lx", "Entry Address:", (int)h.e_entry, h.e_entry);
    //  Program Header Table offset
    printf("\n%-32s[%05d] 0x%016lx", "Program Header Table Offset:", (int)h.e_phoff, h.e_phoff);
    //  Section Table offset
    printf("\n%-32s[%05d] 0x%016lx", "Section Header Table Offset:", (int)h.e_shoff, h.e_shoff);
    //  Flags
    printf("\n%-32s[%05d] 0x%08x", "Flags:", (int)h.e_flags, h.e_flags);
    //  Elf Header Size
    printf("\n%-32s[%05d] 0x%04x", "ELF Header Size:", (int)h.e_ehsize, h.e_ehsize);
    //  Program Header Table Entry Size
    printf("\n%-32s[%05d] 0x%04x", "Program Header Entry Size:", (int)h.e_phentsize, h.e_phentsize);
    //  Program Header Table Entry Num
    printf("\n%-32s[%05d] 0x%04x", "Program Header Entry Num:", (int)h.e_phnum, h.e_phnum);
    //  Section Header Table Entry Size
    printf("\n%-32s[%05d] 0x%04x", "Section Header Entry Size:", (int)h.e_shentsize, h.e_shentsize);
    //  Section Header Table Entry Num
    printf("\n%-32s[%05d] 0x%04x", "Section Header Entry Num:", (int)h.e_shnum, h.e_shnum);
    //  Section Header Table index
    printf("\n%-32s[%05d] 0x%04x", "Section Header String Index:", (int)h.e_shstrndx, h.e_shstrndx);
}

void printPhdrs(Elf64_Ehdr EH, FILE* F, Elf64_Phdr* pHeaders) {
    fseek(F, EH.e_phoff, SEEK_SET);  
    fread(pHeaders, EH.e_phentsize, EH.e_phnum, F); // Index pHeaders

    printf("There are [%d] program headers:\n", EH.e_phnum);
    printf(" No.     Type\t\t Flg Off      VAddr    PAddr    Size     MemImg   MemAlgn");
    for(int i = 0; i < EH.e_phnum; i++) {    
        printf("\n [\x1b[38;5;202m%05d\x1b[0m] ", i);
        printPhdrInfo(pHeaders[i]); 
        if (i == EH.e_phnum-1) {
            printBorder();    
        }
    }
}

void printPhdrInfo(Elf64_Phdr ph) {
    //  p_type
    printf("%-16s", getProgramTypeName(ph.p_type));
    //  p_flags
    if (ph.p_flags & 0x0ff00000) {
        printf("%3s", "PS");
    }
    if (ph.p_flags & 0xf0000000) {
        printf("%3s", "OS");
    } else {
        printf("%3s ", pFlag_Values[ph.p_flags]);
    }
    //  p_offset
    printf("%08lX ", ph.p_offset);
    //  p_vaddr
    printf("%08lX ", ph.p_vaddr);
    //  p_paddr
    printf("%08lX ", ph.p_paddr);
    //  p_filesz
    printf("%08lX ", ph.p_filesz);
    //  p_memsz
    printf("%08lX ", ph.p_memsz);
    //  p_align
    printf("%08lX ", ph.p_align);
}

char *getShStrTab(Elf64_Ehdr EH, FILE* F) {
    //  SHNAME STRTAB
    Elf64_Shdr shstrtab_hdr;
    Elf64_Off shstrtab_offset = EH.e_shoff + (EH.e_shstrndx * EH.e_shentsize);
    
    fseek(F, shstrtab_offset, SEEK_SET);
    fread(&shstrtab_hdr, sizeof(Elf64_Shdr), 1, F);

    char* shstrtab = malloc(shstrtab_hdr.sh_size);
    fseek(F, shstrtab_hdr.sh_offset, SEEK_SET);
    fread(shstrtab, 1, shstrtab_hdr.sh_size, F);

    return(shstrtab);
}

void printShdrs(Elf64_Ehdr EH, FILE* F, Elf64_Shdr* sHeaders, char* shstrtab) {
    fseek(F, EH.e_shoff, SEEK_SET);
    fread(sHeaders, EH.e_shentsize, EH.e_shnum, F); // Index sHeaders

    printf("There are [%d] section headers:\n", EH.e_shnum);
    printf(" No.     Name\t\t     Type\t\t Flags       Addr     Off      Size     Lk If AA ES");
    for(int j = 0; j < EH.e_shnum; j++) {
        printf("\n [\x1b[38;5;202m%05d\x1b[0m]", j);
        printShdrInfo(sHeaders[j], shstrtab);
        if (j == EH.e_shnum-1) {
            printf("\nKey to flags:\n W (write), A (alloc), X (execute), M (merge), S (strings), I (info)\n L (link order), O (extra OS processing required), G (group), T (TLS)\n C (compressed), o (OS specific), p (processor specific)");
            printBorder();
        }
    }
}

void printShdrInfo(Elf64_Shdr sh, const char* strtab) {
    //  sh_name
    printf(" %-20.20s", strtab + sh.sh_name);
    //  sh_type
    printf("%-20s", getSectionTypeName(sh.sh_type));
    //  sh_flags
    if (sh.sh_flags & 0x0ff00000) {
        printf("----------o");
    }
    if (sh.sh_flags & 0xf0000000) {
        printf("----------p");
    }
    printf("%s", sFlag_Values1[sh.sh_flags & 0x0000000F]);
    printf("%s", sFlag_Values2[((sh.sh_flags & 0x000000F0) >> 4) & 0x0F]);
    printf("%s", sFlag_Values3[((sh.sh_flags & 0x00000F00) >> 8) & 0x00F]);
    //  sh_addr
    printf(" %08lX ", sh.sh_addr);
    //  sh_offset
    printf("%08lX ", sh.sh_offset);
    //  sh_size
    printf("%08lX ", sh.sh_size);
    //  sh_link
    printf("%02X ", sh.sh_link);
    //  sh_info
    printf("%02X ", sh.sh_info);
    //  sh_addralign
    printf("%02lX ", sh.sh_addralign);
    //  sh_entsize
    printf("%02lX ", sh.sh_entsize);
}

void printSymtab(Elf64_Shdr* sHeaders, Elf64_Ehdr EH, FILE* F) {
    Elf64_Shdr symTab = {0};
    Elf64_Shdr symStrTabHeader = {0};
    int foundSymtab = 0;
    
    for (int i = 0; i < EH.e_shnum; i++) {
        if (sHeaders[i].sh_type == SHT_SYMTAB) {
            symTab = sHeaders[i];
            if (symTab.sh_link >= EH.e_shnum) {
                printf("invalid symbol table link index.\n");
                printBorder();
                return;
            }
            symStrTabHeader = sHeaders[symTab.sh_link];
            foundSymtab = 1;
            break;
        }
    }
    if (!foundSymtab) {
        printf("No regular symbol table found.\n");
        printBorder();
        return;
    }

    Elf64_Sym *symTabs = malloc(symTab.sh_size);
    if (!symTabs) {
        printf("Failed to allocate memory for symbol table.\n");
        printBorder();
        return;
    }
    if (symTab.sh_entsize == 0) {
        printf("Symbol table entry size is 0; cannot determine symbol count.\n");
        printBorder();
        free(symTabs);
        return;
    }
    if (symTab.sh_size % symTab.sh_entsize != 0) {
        printf("Symbol table size is not evenly divisible by entry size.\n");
        printBorder();
        free(symTabs);
        return;
    }

    Elf64_Xword stEntNum = symTab.sh_size/symTab.sh_entsize;
    char* symstrtab = malloc(symStrTabHeader.sh_size);
    if (!symstrtab) {
        printf("Failed to allocate memory for symbol string table.\n");
        printBorder();
        free(symTabs);
        return;
    }
    fseek(F, symStrTabHeader.sh_offset, SEEK_SET);
    fread(symstrtab, 1, symStrTabHeader.sh_size, F);

    fseek(F, symTab.sh_offset, SEEK_SET);
    fread(symTabs, symTab.sh_entsize, (stEntNum), F);
        
    printf("There are [%d] symbol table entries:\n", (int)stEntNum);
    printf(" No.     %-40s %-10s %-10s %-10s %-8s %-16s %-16s", "Name", "Binding", "Type", "Vis", "Index", "Value", "Size");
    for (int j = 0; j < stEntNum; j++) {
        printf("\n [\x1b[38;5;202m%05d\x1b[0m]", j);
        printSymtabInfo(symTabs[j], symstrtab);
    }

    printBorder();
    free(symTabs);
    free(symstrtab);
}

void printSymtabInfo(Elf64_Sym symEnt, const char* strtab) {
    //  name
    printf(" %-40.40s ", strtab + symEnt.st_name);
    //  info - binding
    // printf("%x", ((symEnt.st_info >> 4) & 0x0F));
    // printf("%x", (symEnt.st_info & 0x0F));
    if (((symEnt.st_info >> 4) & 0x0F) == 0) {
        printf("%-10s", "LOCAL");
    } else if (((symEnt.st_info >> 4) & 0x0F) == 1) {
        printf("%-10s", "GLOBAL");
    } else if (((symEnt.st_info >> 4) & 0x0F) == 2) {
        printf("%-10s", "WEAK");
    } else if (((symEnt.st_info >> 4) & 0x0F) >= 0xA && ((symEnt.st_info >> 4) & 0x0F) <= 0xC) {
        printf("%-10s", "OS_SPEC");
    } else if (((symEnt.st_info >> 4) & 0x0F) >= 0xD && ((symEnt.st_info >> 4) & 0x0F) <= 0xF) {
        printf("%-10s", "PROC_SPEC");
    } else {
        printf("%-10s", "UNKNOWN");
    }
    //  info - type
    if ((symEnt.st_info & 0x0F) == 0) {
        printf(" %-10s", "NOTYPE");
    } else if ((symEnt.st_info & 0x0F) == 1) {
        printf(" %-10s", "OBJECT");
    } else if ((symEnt.st_info & 0x0F) == 2) {
        printf(" %-10s", "FUNC");
    } else if ((symEnt.st_info & 0x0F) == 3) {
        printf(" %-10s", "SECTION");
    } else if ((symEnt.st_info & 0x0F) == 4) {
        printf(" %-10s", "FILE");
    } else if ((symEnt.st_info & 0x0F) == 5) {
        printf(" %-10s", "COMMON");
    } else if ((symEnt.st_info & 0x0F) == 6) {
        printf(" %-10s", "TLS");
    } else if ((symEnt.st_info & 0x0F) >= 0xA && (symEnt.st_info & 0x0F) <= 0xC) {
        printf(" %-10s", "OS_SPEC");
    } else if ((symEnt.st_info & 0x0F) >= 0xD && (symEnt.st_info & 0x0F) <= 0xF) {
        printf(" %-10s", "PROC_SPEC");
    } else {
        printf(" %-10s", "UNKNOWN");
    }
    //  other
    if (symEnt.st_other == 0) {
        printf(" %-10s", "DEFAULT");
    } else if (symEnt.st_other == 1) {
        printf(" %-10s", "INTERNAL");
    } else if (symEnt.st_other == 2) {
        printf(" %-10s", "HIDDEN");
    } else if (symEnt.st_other == 3) {
        printf(" %-10s", "PROTECTED");
    } else {
        printf(" %-10s", "UNKNOWN");
    }
    //  shndx
    printf(" %08X", symEnt.st_shndx);
    //  value
    printf(" %016lX", symEnt.st_value);
    //  size
    printf(" %016lX", symEnt.st_size);


}

// DECODE

LoadedSection loadSectionByName(Elf64_Ehdr EH, Elf64_Shdr* sHeaders, FILE* F, char* shstrtab, const char *name) {
    LoadedSection result = {0};
    
    for(int i = 0; i < EH.e_shnum; i++) {
        if(strcmp(shstrtab + sHeaders[i].sh_name, name) == 0) {
            result.header = sHeaders[i];
            result.found = 1;
            break;
        }
    }

    if (!result.found) {
        return result;
    }
    if (result.header.sh_size == 0) {
        return result;
    }

    result.bytes = malloc(result.header.sh_size);
    if(!result.bytes) {
        result.found = 0;
        return result;
    }

    fseek(F, result.header.sh_offset, SEEK_SET);
    if(fread(result.bytes,1, result.header.sh_size, F) != result.header.sh_size) {
        free(result.bytes);
        result.bytes = NULL;
        result.found = 0;
        return result;
    }

    return result;
}

void decodeTextSection(const unsigned char *bytes, size_t size, uint64_t baseAddr) {
    size_t offset = 0;

    while (offset < size) {
        Instruction inst = {0};
        size_t len = decodeInstruction(bytes+offset, size-offset, baseAddr + offset, &inst);

        if (len == 0) {
            inst.address = baseAddr + offset;
            inst.bytes[0] = bytes[offset];
            inst.length = 1;
            snprintf(inst.mnemonic, sizeof(inst.mnemonic), "db");
            snprintf(inst.operands, sizeof(inst.operands), "0x%02X", bytes[offset]);
            len = 1;
        }

        char byteStr[64] = {0};
        char *p = byteStr;

        for (size_t i = 0; i < inst.length; i++) {
            p += snprintf(p, sizeof(byteStr) - (p - byteStr), "%02X ", inst.bytes[i]);
        }

        printf(" [0x\x1b[38;5;202m%08lx\x1b[0m]: %-20s %s %s\n", inst.address, byteStr, inst.mnemonic, inst.operands);

        offset += len;
    }
}

void disassembleSection(Elf64_Ehdr EH, Elf64_Shdr *sHeaders, FILE *F, char *shstrtab) {
    printf("Disassembly of section [.text]:\n");    

    LoadedSection text = loadSectionByName(EH, sHeaders, F, shstrtab, ".text"); // Just do .text for now
    if (!text.found) {
        printf("No data found.\n");
        return;
    }

    decodeTextSection(text.bytes, text.header.sh_size, text.header.sh_addr);
    free(text.bytes);
}

size_t decodeInstruction(const unsigned char* code, size_t maxLength, uint64_t addr, Instruction *inst) {
    PrefixState ps;
    size_t offset = 0;

    memset(inst, 0, sizeof(*inst));
    inst->address = addr;

    offset = parsePrefixes(code, maxLength, &ps);

    for (size_t i = 0; i < offset; i++) {
        inst->bytes[i] = code[i];
    }
    inst->length = offset;

    if (offset >= maxLength) {
        return 0;
    }

    int opcodeParsed = parseOpcode(code, maxLength, &ps, inst, offset); 

    if (opcodeParsed == 1) {
        return inst->length;
    } else {
        return 0;
    }
}

// Decode Helper Functions
int isPrefix(unsigned char b) {
    if (b >= 0x40 && b <= 0x4F)
        return 1; // REX
    switch (b) {
        case 0xF0:
        case 0xF2:
        case 0xF3:
        case 0x2E:
        case 0x36:
        case 0x3E:
        case 0x26:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
            return 1;
        default:
            return 0;
    }
}

size_t parsePrefixes(const unsigned char* code, size_t maxLength, PrefixState *ps) {
    size_t offset = 0;
    memset(ps, 0, sizeof(*ps));

    while (offset < maxLength && isPrefix(code[offset])) {
        unsigned char b = code[offset];

        if (b >= 0x40 && b <= 0x4F) {   // Parse REX
            ps->rex = b;
            ps->has_rex = 1;

            ps->rexW = (ps->rex >> 3) & 0x01;
            ps->rexR = (ps->rex >> 2) & 0x01;
            ps->rexX = (ps->rex >> 1) & 0x01;
            ps->rexB = ps->rex & 0x01; 
        } else {    // Parse Legacy
            if (ps->legacy_count < 4) {
                ps->legacy[ps->legacy_count] = b;
                ps->legacy_count++;
            }

            switch (b) {
                case 0xF3: ps->rep = 1; break;
                case 0x66: ps->operand_size_override = 1; break;
            }
        }
        offset++;
    }
    return offset;
}

int parseOpcode (const unsigned char* code, size_t maxLength, PrefixState *ps, Instruction *inst, size_t offset) {
    // ENDBR64
    if (code[offset] == 0x0F) {
        if(offset + 2 < maxLength) {
            unsigned char op1 = code[offset + 1];
            unsigned char op2 = code[offset + 2];
            if (ps->rep == 1 && op1 == 0x1E && op2 == 0xFA) {
                inst->bytes[inst->length++] = code[offset++];
                inst->bytes[inst->length++] = code[offset++];
                inst->bytes[inst->length++] = code[offset++];
                snprintf(inst->mnemonic, sizeof(inst->mnemonic), "endbr64");
                return 1;   // Success
            }
        }
    }

    // 31 - XOR
    if (code[offset] == 0x31) {
        ModRM rm;
        snprintf(inst->mnemonic, sizeof(inst->mnemonic), "XOR");
        inst->bytes[inst->length++] = code[offset];

        int ModRMparsed = parseModRM(code, maxLength, &rm, ps, inst, offset);      
        return ModRMparsed;    
    }

    // 89 - MOV
    if (code[offset] == 0x89) {
        ModRM rm;
        snprintf(inst->mnemonic, sizeof(inst->mnemonic), "MOV");
        inst->bytes[inst->length++] = code[offset];

        int ModRMparsed = parseModRM(code, maxLength, &rm, ps, inst, offset);
        return ModRMparsed;
    }

    // 5E - POP RSI
    if (code[offset] == 0x5E) {
        snprintf(inst->mnemonic, sizeof(inst->mnemonic), "POP rsi");
        inst->bytes[inst->length++] = code[offset];
        return 1;
    }

    // 83 - ADD, OR, ADC, SBB, AND, SUB, XOR, CMP - Immediate to Register/Memory
    if (code[offset] == 0x83) {
        ModRM rm;
        inst->bytes[inst->length++] = code[offset];
        int ModRMparsed = parseModRM(code, maxLength, &rm, ps, inst, offset);
        snprintf(inst->mnemonic, sizeof(inst->mnemonic), "%s", detExtension(rm));

        return ModRMparsed;
    }
    return 0; // Fail
}

int parseModRM (const unsigned char* code, size_t maxLength, ModRM *rm, PrefixState *ps, Instruction *inst, size_t offset) {
    if (offset + 1 >= maxLength) {
        return 0;   // No byte at offset+1
    }
    
    // Splits up modR/M byte
    uint8_t byte = code[offset + 1];

    rm->mod = (byte >> 6) & 0x03;
    rm->reg = (byte >> 3) & 0x07;
    rm->rm  = byte & 0x07;

    inst->bytes[inst->length++] = byte;

    // determine width
    uint8_t width;
    if (ps->has_rex && ps->rexW == 1) {
        width = 64;
    } else if (ps->operand_size_override == 1) {
        width = 16;
    } else {
        width = 32;
    }

    if(code[offset] == 83) {
        return 0;
    }
    
    if (rm->mod == 3) {
        const char* detRM = {0};
        const char* detREG = {0};

        if (ps->rexR != 1 && ps->rexX != 1 && ps->rexB != 1) {
            detRM = getRegisterLegacy(rm->rm, width);
            detREG = getRegisterLegacy(rm->reg, width);
        } 

        if (ps->rexR != 1 && ps->rexX != 1 && ps->rexB == 1) {
            detRM = getRegisterREX(rm->rm, width);
            detREG = getRegisterLegacy(rm->reg, width);
        }
        
        snprintf(inst->operands, sizeof(inst->operands), "%s, %s", detRM, detREG);
        return 1;
    }
}

const char* getRegisterLegacy(uint8_t reg, uint8_t width) {
    if (width == 16) {
        return bit16[reg];
    } else if (width == 32) {
        return bit32[reg];
    } else if (width == 64) {
        return bit64[reg];
    } else {
        return "???";
    }
}

const char* getRegisterREX(uint8_t reg, uint8_t width) {
    if (width == 16) {
        return rex16[reg];
    } else if (width == 32) {
        return rex32[reg];
    } else if (width == 64) {
        return rex64[reg];
    } else {
        return "???";
    }
}

const char* detExtension(ModRM rm) {
    const char* detOP;
    switch(rm.reg) {
        case 0: detOP = "ADD"; break;
        case 1: detOP = "OR"; break;
        case 2: detOP = "ADC"; break;
        case 3: detOP = "SBB"; break;
        case 4: detOP = "AND"; break;
        case 5: detOP = "SUB"; break;
        case 6: detOP = "XOR"; break;
        case 7: detOP = "CMP"; break;
        default: detOP = "???"; break;
    }
    return detOP;
}



