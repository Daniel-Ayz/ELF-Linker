#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <string.h>

#define MAX_ELF_FILES 2

typedef void (*menu_function)();

int debug_mode = 0;
int fd[MAX_ELF_FILES] = {-1, -1}; // File descriptors for ELF files
void* map_start[MAX_ELF_FILES]; // Pointers to memory-mapped ELF files
size_t map_size[MAX_ELF_FILES] = {0}; // To store the size of each mapping



// Function prototypes
void toggle_debug_mode();
void examine_elf_file();
void print_section_names();
void print_symbols();
void check_files_for_merge();
void merge_elf_files();
void quit_program();
void display_menu();
int open_and_map_elf_file(const char* filename, int index);

struct menu_option {
    char* name;
    menu_function func;
} menu_options[] = {
    {"Toggle Debug Mode", toggle_debug_mode},
    {"Examine ELF File", examine_elf_file},
    {"Print Section Names", print_section_names},
    {"Print Symbols", print_symbols},
    {"Check Files for Merge", check_files_for_merge},
    {"Merge ELF Files", merge_elf_files},
    {"Quit", quit_program},
    {NULL, NULL} // Sentinel to mark the end of the array
};




int main() {
    int choice;
    //char choise[3];
    do {
        display_menu();
        scanf("%d", &choice);
        if(choice >= 0 && choice < sizeof(menu_options) / sizeof(struct menu_option) - 1) {
            menu_options[choice].func();
        } else {
            printf("Invalid option.\n");
        }
    } while(choice != 6); // Option 6 is Quit
    return 0;
}

// int main(int argc, char **argv){
//     //vars
//     char choise[3];
//     link* virus_list = NULL;
//     struct fun_desc menu[] = { { "Load signatures", load_signatures_wrap }, { "Print signatures", list_print_wrap }, { "Detect viruses", detect_viruses }, { "Fix file", fix_file }, { "Quit", quit },{ NULL, NULL } };
//     FILE* file_to_scan = NULL;
//     if(argc > 1){
//         file_to_scan = fopen(argv[1], "r+b");
//     }

//     //find size of menu
//     int i = 0;
//     struct fun_desc p = menu[i];
//     while(p.name != NULL){
//         p = menu[++i];
//     }
//     char ascii_i = i + '0';

//     //Main menu
//     printf("Select operation from the following menu:\n");
//     for(int option=0; option<i; option++){
//         printf("%d) %s\n", option, menu[option].name);
//     }
//     printf("Option:");
//     while(fgets(choise, 3, stdin) != NULL){
//         int number = atoi(&choise[0]);
//         // int number = atoi(&choise[0]);
//         // if ( number < 0 || i <= number){
//         //     printf("Not within bounds\n");
//         //     exit(1);
//         // }
//         if(choise[0] < '0' || ascii_i <= choise[0]){
//             printf("Not within bounds\n");
//             exit(1);
//         }
//         printf("\nWithin bounds\n");
//         virus_list = run_function(virus_list, file_to_scan, menu[number].fun);
//         printf("Done.\n\n");

//         printf("Select operation from the following menu:\n");
//         for(int option=0; option<i; option++){
//             printf("%d) %s\n", option, menu[option].name);
//         }
//         printf("Option:");
//     }
// }

void display_menu() {
    printf("Choose action:\n");
    for(int i = 0; menu_options[i].name != NULL; i++) {
        printf("%d-%s\n", i, menu_options[i].name);
    }
}

void toggle_debug_mode() {
    debug_mode = !debug_mode;
    printf("Debug mode %s.\n", debug_mode ? "on" : "off");
}

void examine_elf_file() {
    char filename[256];
    int fileIndex = -1;

    // Find an available slot
    for (int i = 0; i < MAX_ELF_FILES; ++i) {
        if (fd[i] == -1) { // Slot is available
            fileIndex = i;
            break;
        }
    }
    if (fileIndex == -1) {
        printf("Maximum number of ELF files are already opened.\n");
        return;
    }

    printf("Enter ELF file name: ");
    scanf("%s", filename);

    // Open and map the ELF file
    if (open_and_map_elf_file(filename, fileIndex) != 0) {
        // Error handling is done within the open_and_map_elf_file function
        return;
    }

    // Assuming the file is valid and mapped, read the ELF header
    Elf32_Ehdr* header = (Elf32_Ehdr*)map_start[fileIndex];

    // Print requested information
    printf("Magic: %c%c%c\n", header->e_ident[EI_MAG1], header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);
    printf("Data: ");
    switch (header->e_ident[EI_DATA]) {
        case ELFDATANONE: printf("Invalid data encoding\n"); break;
        case ELFDATA2LSB: printf("2's complement, little endian\n"); break;
        case ELFDATA2MSB: printf("2's complement, big endian\n"); break;
        default: printf("Unknown data encoding\n");
    }
    printf("Entry point address: 0x%x\n", header->e_entry);
    printf("Start of section headers: %ld (bytes into file)\n", (long)header->e_shoff);
    printf("Number of section headers: %d\n", header->e_shnum);
    printf("Size of section headers: %d (bytes)\n", header->e_shentsize);
    printf("Start of program headers: %ld (bytes into file)\n", (long)header->e_phoff);
    printf("Number of program headers: %d\n", header->e_phnum);
    printf("Size of program headers: %d (bytes)\n", header->e_phentsize);
}

void print_section_names() {
    int printed = 0;
    for (int fileIndex = 0; fileIndex < MAX_ELF_FILES; ++fileIndex) {
        if (fd[fileIndex] == -1) continue; // Skip if file is not opened

        Elf32_Ehdr *header = (Elf32_Ehdr *)map_start[fileIndex];
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)map_start[fileIndex] + header->e_shoff);
        const char *str_tab = (char *)map_start[fileIndex] + section_headers[header->e_shstrndx].sh_offset;

        printf("File: %d\n", fileIndex); // Replace with actual filename if stored
        for (int i = 0; i < header->e_shnum; ++i) {
            printf("[%d] %s 0x%08x 0x%06x 0x%06x %d\n",
                   i,
                   &str_tab[section_headers[i].sh_name],
                   section_headers[i].sh_addr,
                   section_headers[i].sh_offset,
                   section_headers[i].sh_size,
                   section_headers[i].sh_type);

             printed = 1;
        }
        if (debug_mode) {
            printf("shstrndx: %d\n", header->e_shstrndx);
        }
    }
    if (!printed) {
        printf("Error: No ELF files are currently mapped.\n");
    }
}

void print_symbols() {
    int printed = 0;
    for (int fileIndex = 0; fileIndex < MAX_ELF_FILES; ++fileIndex) {
        if (fd[fileIndex] == -1) continue; // Skip if file is not opened

        Elf32_Ehdr *header = (Elf32_Ehdr *)map_start[fileIndex];
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)map_start[fileIndex] + header->e_shoff);
        const char *sh_str_tab = (char *)map_start[fileIndex] + section_headers[header->e_shstrndx].sh_offset;

        printf("File: %d\n", fileIndex); // Replace with actual filename if stored

        for (int i = 0; i < header->e_shnum; i++) {
            if (section_headers[i].sh_type == SHT_SYMTAB || section_headers[i].sh_type == SHT_DYNSYM) {
                Elf32_Sym *symtab = (Elf32_Sym *)((char *)map_start[fileIndex] + section_headers[i].sh_offset);
                int num_symbols = section_headers[i].sh_size / section_headers[i].sh_entsize;
                const char *str_tab = (char *)map_start[fileIndex] + section_headers[section_headers[i].sh_link].sh_offset;

                if (debug_mode) {
                    printf("Symbol table size: %d, Number of symbols: %d\n", section_headers[i].sh_size, num_symbols);
                }

                for (int j = 0; j < num_symbols; j++) {
                    const char *sym_name = &str_tab[symtab[j].st_name];
                    int sec_index = symtab[j].st_shndx;
                    const char *sec_name = (sec_index < header->e_shnum) ? &sh_str_tab[section_headers[sec_index].sh_name] : "N/A";

                    printf("[%d] 0x%08x %d %s %s\n",
                           j,
                           symtab[j].st_value,
                           sec_index,
                           sec_name,
                           sym_name);

                    printed = 1;
                }
            }
        }
    }

    if (!printed) {
        printf("Error: No symbols found or no ELF files are currently mapped.\n");
    }
}


void check_files_for_merge() {
    if (fd[0] == -1 || fd[1] == -1) {
        printf("Error: Two ELF files must be opened and mapped.\n");
        return;
    }

    Elf32_Ehdr* header[MAX_ELF_FILES];
    Elf32_Shdr* section_headers[MAX_ELF_FILES];
    Elf32_Sym* symtab[MAX_ELF_FILES];
    int symtab_size[MAX_ELF_FILES] = {0};
    const char* strtab[MAX_ELF_FILES];

    for (int i = 0; i < MAX_ELF_FILES; i++) {
        header[i] = (Elf32_Ehdr*)map_start[i];
        section_headers[i] = (Elf32_Shdr*)((char*)map_start[i] + header[i]->e_shoff);

        // Find the symbol table and associated string table for each file
        for (int sh_idx = 0; sh_idx < header[i]->e_shnum; sh_idx++) {
            if (section_headers[i][sh_idx].sh_type == SHT_SYMTAB) {
                symtab[i] = (Elf32_Sym*)((char*)map_start[i] + section_headers[i][sh_idx].sh_offset);
                symtab_size[i] = section_headers[i][sh_idx].sh_size / sizeof(Elf32_Sym);
                //strtab[i] = (char*)map_start[i] + section_headers[section_headers[i][sh_idx].sh_link].sh_offset;
                int strtab_section_index = section_headers[i][sh_idx].sh_link;
                Elf32_Shdr* strtab_section_header = &section_headers[i][strtab_section_index];
                strtab[i] = (char*)map_start[i] + strtab_section_header->sh_offset;
                break;
            }
        }

        if (symtab_size[i] == 0) {
            printf("Feature not supported: No symbol table found in one of the files.\n");
            return;
        }
    }

    // Check and compare symbols between the two ELF files
    for (int i = 0; i < MAX_ELF_FILES; i++) {
        int other = (i + 1) % MAX_ELF_FILES; // Index of the other file

        for (int sym_idx = 1; sym_idx < symtab_size[i]; sym_idx++) { // Skip dummy symbol
            Elf32_Sym* sym = &symtab[i][sym_idx];
            const char* sym_name = &strtab[i][sym->st_name];
            
            //printf("sym_name: %s\n", sym_name);
            if (strcmp(sym_name, "") == 0) {
               // Skip symbols with empty names
                continue;
            }

            if (sym->st_shndx == SHN_UNDEF) { // Undefined symbol
                // Check if symbol is defined in the other ELF file
                int found = 0, defined = 0;
                for (int osym_idx = 1; osym_idx < symtab_size[other]; osym_idx++) {
                    Elf32_Sym* osym = &symtab[other][osym_idx];
                    if (strcmp(sym_name, &strtab[other][osym->st_name]) == 0) {
                        found = 1;
                        if (osym->st_shndx != SHN_UNDEF) {
                            defined = 1;
                            break;
                        }
                    }
                }
                if (!found || !defined) {
                    printf("Symbol %s undefined.\n", sym_name);
                }
            }
            else { // Defined symbol
                // Check if symbol is multiply defined in the other ELF file
                for (int osym_idx = 1; osym_idx < symtab_size[other]; osym_idx++) {
                    Elf32_Sym* osym = &symtab[other][osym_idx];
                    // if (strcmp(sym_name, &strtab[other][osym->st_name]) == 0 && osym->st_shndx != SHN_UNDEF) {
                    //     printf("Symbol %s multiply defined.\n", sym_name);
                    //     break;
                    // }
                    if (strcmp(sym_name, &strtab[other][osym->st_name]) == 0) {
                        if (sym->st_shndx != SHN_UNDEF && osym->st_shndx != SHN_UNDEF) {
                            printf("Symbol %s multiply defined.\n", sym_name);
                        }
                    }
                }
            }
        }
    }
}
   

void merge_elf_files() {
    printf("Not implemented yet.\n");
}

void quit_program() {
    for(int i = 0; i < MAX_ELF_FILES; i++) {
        if(fd[i] != -1) {
            if (map_start[i] != MAP_FAILED) {
                munmap(map_start[i], map_size[i]); // Use the stored size
                map_size[i] = 0; // Reset the stored size
            }
            close(fd[i]);
            fd[i] = -1;
            map_start[i] = MAP_FAILED;
        }
    }
    printf("Exiting program.\n");
    exit(0);
}

int open_and_map_elf_file(const char* filename, int index) {
    if (index < 0 || index >= MAX_ELF_FILES) {
        printf("Invalid file index.\n");
        return -1;
    }

    // Close and unmap previously opened file if any
    if (fd[index] != -1) {
        munmap(map_start[index], map_size[index]);
        close(fd[index]);
        fd[index] = -1;
        map_start[index] = MAP_FAILED;
    }

     // Open the file
    fd[index] = open(filename, O_RDONLY);
    if (fd[index] == -1) {
        perror("Error opening file");
        return -1;
    }

    // Obtain the size of the file
    struct stat st;
    if (fstat(fd[index], &st) == -1) {
        perror("Error obtaining file size");
        close(fd[index]);
        fd[index] = -1;
        return -1;
    }

     // Memory map the file
    map_start[index] = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd[index], 0);
    if (map_start[index] == MAP_FAILED) {
        perror("Error mapping file");
        close(fd[index]);
        fd[index] = -1;
        return -1;
    }

    // Validate ELF header
    Elf32_Ehdr* header = (Elf32_Ehdr*)map_start[index];
    if (header->e_ident[EI_MAG0] != ELFMAG0 ||
        header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 ||
        header->e_ident[EI_MAG3] != ELFMAG3) {
        printf("Error: Not an ELF file.\n");
        munmap(map_start[index], st.st_size);
        close(fd[index]);
        fd[index] = -1;
        map_start[index] = MAP_FAILED;
        return -1;
    }

    // Successfully mapped ELF file
    return 0;
}

