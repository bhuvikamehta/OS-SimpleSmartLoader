#define _GNU_SOURCE
#include "loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

int fd, page_faults = 0;
double allocated_pages = 0;
double fragmentation = 0;
Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
struct sigaction sa;

// Helper Functions
void free_elf_header() {
    if (ehdr) {
        free(ehdr);
        ehdr = NULL;
    }
}

void free_program_headers() {
    if (phdr) {
        free(phdr);
        phdr = NULL;
    }
}

void cleanup() {
    free_elf_header();
    free_program_headers();
    close(fd);
}

// Loads the ELF header from the file descriptor
void load_elf_header(int fd) {
    ehdr = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    if (!ehdr) {
        perror("Failed to allocate memory for ELF header");
        exit(1);
    }
    if (read(fd, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
        perror("Failed to read ELF header");
        exit(1);
    }
}

// Loads program headers from the file descriptor
void load_program_headers(int fd) {
    phdr = (Elf32_Phdr *)malloc(ehdr->e_phentsize * ehdr->e_phnum);
    lseek(fd, ehdr->e_phoff, SEEK_SET);
    if (read(fd, phdr, ehdr->e_phentsize * ehdr->e_phnum) != ehdr->e_phentsize * ehdr->e_phnum) {
        perror("Failed to read program headers");
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
                    perror("Memory mapping failed");
                    exit(1);
                }
                lseek(fd, phdr[i].p_offset, SEEK_SET);
                if (read(fd, mapped_memory, phdr[i].p_filesz) != phdr[i].p_filesz) {
                    perror("Failed to read segment data into memory");
                    exit(1);
                }
                allocated_pages += (double)size_needed / 4096;
                fragmentation += (size_needed - phdr[i].p_memsz);
                return;
            }
        }
    }
}

// Initialize the loader and set up the signal handler
void setup_loader(char *file) {
    fd = open(file, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open file");
        exit(1);
    }
    load_elf_header(fd);
    load_program_headers(fd);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segfault_handler;
    sigaction(SIGSEGV, &sa, NULL);
}

// Entry point to run the ELF executable
void execute_entry_point() {
    int (*entry)() = (int (*)())ehdr->e_entry;
    int result = entry();
    printf("Program returned: %d\n", result);
}

// Main function
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
        return 1;
    }
    setup_loader(argv[1]);
    execute_entry_point();

    // Summary of page faults and memory usage
    printf("Page Faults: %d\n", page_faults);
    printf("Allocated Pages: %f\n", allocated_pages);
    printf("Fragmented Memory: %f KB\n", fragmentation / 1024);
    
    cleanup();
    return 0;
}
