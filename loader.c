#define _GNU_SOURCE
#include "loader.h"
#include <signal.h>

int count = 0;
int page_faults = 0;
int page_allocations = 0;
double fragmented_memory = 0.0;

Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd;

void loader_cleanup() {
    if (ehdr) {
        free(ehdr);
        ehdr = NULL;
    }
    if (phdr) {
        free(phdr);
        phdr = NULL;
    }
}

void segfault_handler(int signo, siginfo_t *si, void *context) {
    printf("Caught segfault at address %p\n", si->si_addr);
    page_faults++;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if ((int)si->si_addr >= (int)phdr[i].p_vaddr && (int)si->si_addr < (int)(phdr[i].p_vaddr + phdr[i].p_memsz)) {
                int page_size = 4096;
                int page_start = (int)phdr[i].p_vaddr & ~(page_size - 1);
                int page_end = ((int)(phdr[i].p_vaddr + phdr[i].p_memsz) + page_size - 1) & ~(page_size - 1);
                int num_pages = (page_end - page_start) / page_size;

                for (int j = 0; j < num_pages; j++) {
                    void *mem = mmap((void *)(page_start + j * page_size), page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                    if (mem == MAP_FAILED) {
                        printf("Error mapping memory\n");
                        exit(1);
                    }
                    page_allocations++;

                    lseek(fd, phdr[i].p_offset + j * page_size, SEEK_SET);
                    if (read(fd, mem, page_size) != page_size) {
                        printf("Error reading from file\n");
                        exit(1);
                    }
                }

                int fragmented_bytes = (int)phdr[i].p_memsz % page_size;
                if (fragmented_bytes > 0) {
                    fragmented_memory += (double)fragmented_bytes / 1024.0;
                }

                int (*_start)() = (int (*)())((int)phdr[i].p_vaddr + (ehdr->e_entry - phdr[i].p_vaddr));
                int result = _start();
                printf("User _start return value = %d\n", result);
                return;
            }
        }
    }

    printf("Segfault not handled\n");
    exit(1);
}

void load_and_run_elf(char **argv) {
    fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        printf("Error opening file\n");
        exit(1);
    }

    ehdr = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    if (read(fd, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
        printf("Error reading ELF header\n");
        close(fd);
        exit(1);
    }

    phdr = (Elf32_Phdr *)malloc(sizeof(Elf32_Phdr) * ehdr->e_phnum);
    lseek(fd, ehdr->e_phoff, SEEK_SET);
    if (read(fd, phdr, sizeof(Elf32_Phdr) * ehdr->e_phnum) != sizeof(Elf32_Phdr) * ehdr->e_phnum) {
        printf("Error reading program headers\n");
        close(fd);
        exit(1);
    }

    struct sigaction sa;
    sa.sa_sigaction = segfault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    int (*_start)() = (int (*)())ehdr->e_entry;
    int result = _start();
    printf("User _start return value = %d\n", result);

    printf("Total page faults: %d\n", page_faults);
    printf("Total page allocations: %d\n", page_allocations);
    printf("Total fragmented memory: %.2f KB\n", fragmented_memory);

    loader_cleanup();
    close(fd);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <ELF Executable>\n", argv[0]);
        exit(1);
    }

    load_and_run_elf(argv);
    return 0;
}
