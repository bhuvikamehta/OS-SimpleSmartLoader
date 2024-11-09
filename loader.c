#define _GNU_SOURCE
#include "loader.h"
#include <signal.h>
#include <sys/stat.h>

int fd, page_faults = 0;
int allocated_pages = 0;
double fragmentation = 0;
Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
struct sigaction sa;


void loader_cleanup() {
    free(ehdr);
    free(phdr);
    close(fd);
}

int check_file(Elf32_Ehdr *eehdr) {
    char elf_magicno[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
    if ((ehdr->e_ident[0] == elf_magicno[0]) &&
        (ehdr->e_ident[1] == elf_magicno[1]) &&
        (ehdr->e_ident[2] == elf_magicno[2]) &&
        (ehdr->e_ident[3] == elf_magicno[3])){
            return 1; // true
        } 
    else {
        return 0; // false
    }
  }

void load_elf_header(char** argv) {
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("Error opening the file");
        printf("\n");
        exit(1);
    }

    // 1. Load entire binary content into the memory from the ELF file.

    int elf_size = lseek(fd, 0, SEEK_END); // Determine the file size
    int ptr = lseek(fd, 0, SEEK_SET); // Reset the pointer back to the beginning
    if (ptr < 0) {
        printf("ptr is not at beginning.");
        printf("\n");
        exit(1);
    }

    char* elf_data = (char*)malloc(elf_size);
    int read_length = read(fd, elf_data, elf_size); // Read ELF file content into elf_data
    if (read_length < 0) {  
        printf("could not read the file");
        printf("\n");
        exit(1);
    }

    // Loads the ELF header from the file descriptor
    ehdr = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    ptr = lseek(fd, 0, SEEK_SET); // reset the ptr back to beginning.
    if (ptr < 0) {
        printf("ptr is not at beginning.");
        exit(1);
    }
    read_length = read(fd, ehdr, sizeof(Elf32_Ehdr)); // Read ELF header into elf_header_data
    if (read_length < 0) {
        printf("could not read the file");
        printf("\n");
        exit(1);
    }

    int valid_elf_file = check_file(ehdr);
    if (valid_elf_file == 0) {
        printf("Not a valid ELF File");
        printf("\n");
        exit(1);
    }

// Reading ELF program header
    phdr = (Elf32_Phdr *)malloc(sizeof(Elf32_Phdr) * ehdr->e_phnum);
    ptr = lseek(fd, ehdr->e_phoff, SEEK_SET);
    if (ptr < 0) {
        printf("lseek() command failed.");
        printf("\n");
        exit(1);
    }
    read_length = read(fd, phdr, sizeof(Elf32_Phdr) * ehdr->e_phnum); // Read the program header table into program_header_data
    if (read_length < 0) {
        printf("could not read the file");
        exit(1);
    }

    // 2. Iterate through the PHDR table and find the section of PT_LOAD 
  //    type that contains the address of the entrypoint method in fib.c

    Elf32_Phdr *target_segment = NULL;
    int i = 0;
    while (i <ehdr->e_phnum) {
        if ((phdr[i].p_type == PT_LOAD) && (ehdr->e_entry < phdr[i].p_vaddr + phdr[i].p_memsz)){
            target_segment = &phdr[i];
            break;
        }
        i++;
    }

    if (target_segment == NULL) {
        printf("PT_LOAD segment having the entrypoint is not present");
        printf("\n");
        exit(1);
    }

    // 3. Allocate memory of the size "p_memsz" using mmap function 
    //    and then copy the segment content
    void *virtual_mem = mmap(NULL, target_segment->p_memsz, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (virtual_mem == MAP_FAILED) {
        printf("Error mapping memory");
        printf("\n");
        exit(1);
    }

    ptr = lseek(fd, target_segment->p_offset, SEEK_SET);
    if (ptr < 0) {
        printf("Could not seek to the segment start");
        exit(1);
    }
    int read_segment_result = read(fd, virtual_mem, target_segment->p_memsz); // Load the segment into the allocated memory
    if (read_segment_result < 0) {
        printf("could not read the file");
        printf("\n");
        exit(1);
    }
}


// Calculate page size based on segment size
size_t page_size(size_t mem_size) {
    size_t size = 0;
    while (size < mem_size) size += 4096;
    return size;
}

// Handles segmentation faults and maps pages when accessed
void segfault_handler(int signo, siginfo_t *si, void *context) {
    page_faults++;
    printf("Caught segmentation fault at address: %p\n", si->si_addr);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if ((int)si->si_addr >= phdr[i].p_vaddr && (int)si->si_addr < (phdr[i].p_vaddr + phdr[i].p_memsz)) {
                size_t size_needed = page_size(phdr[i].p_memsz);
                void *mapped_memory = mmap((void *)phdr[i].p_vaddr, size_needed, PROT_READ | PROT_WRITE | PROT_EXEC,
                                           MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
                if (mapped_memory == MAP_FAILED) {
                    printf("Memory mapping failed");
                    printf("\n");
                    loader_cleanup();
                    exit(EXIT_FAILURE);
                }
                lseek(fd, phdr[i].p_offset, SEEK_SET);
                if (read(fd, mapped_memory, phdr[i].p_filesz) != phdr[i].p_filesz) {
                    printf("Failed to read segment data into memory");
                    printf("\n");
                    exit(1);
                }
                allocated_pages += (int)size_needed / 4096;
                fragmentation += (size_needed - phdr[i].p_memsz);
                return;
            }
        }
    }
}

// Main function
int main(int argc, char **argv) {
    // Checks whether only one argument is passed
    if (argc != 2) {
        printf("Usage: %s <ELF Executable>\n", argv[0]);
        exit(1);
    }
    load_elf_header(argv);

    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segfault_handler;
    sigaction(SIGSEGV, &sa, NULL);

    // Entry point to run the ELF executable
    int (*_start)() = (int (*)())ehdr->e_entry;
    int result = _start();
    printf("Program returned: %d\n", result);

    // Summary of page faults and memory usage
    printf("Page Faults: %d\n", page_faults);
    printf("Allocated Pages: %d\n", allocated_pages);
    printf("Fragmented Memory: %f KB\n", fragmentation / 1024);
    
    loader_cleanup();
    return 0;
}
