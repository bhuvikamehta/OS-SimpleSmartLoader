#include "loader.h"
#include <signal.h>
#include <sys/user.h>
#include <ucontext.h>

#define PAGE_SIZE 4096
#define MIN(a,b) ((a) < (b) ? (a) : (b))

// Global variables to track statistics
static int total_page_faults = 0;
static int total_page_allocations = 0;
static int total_internal_fragmentation = 0;

// Global variables needed for segment loading
static Elf32_Ehdr *ehdr;
static Elf32_Phdr *phdr;
static int fd;
static char* elf_data;
static int elf_size;

// Structure to track loaded segments
typedef struct {
    uintptr_t start_addr;  // Using uintptr_t for pointer-sized addresses
    size_t size;
    size_t offset;
    void* mapped_addr;
} LoadedSegment;

#define MAX_SEGMENTS 10
static LoadedSegment loaded_segments[MAX_SEGMENTS];
static int num_loaded_segments = 0;

// Function prototypes
static void segfault_handler(int sig, siginfo_t *si, void *unused);
static int load_page_for_address(void* fault_addr);
static Elf32_Phdr* find_segment_for_address(uintptr_t addr);

/*
 * Initialize signal handler for segmentation faults
 */
static void setup_segfault_handler() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segfault_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        printf("Error setting up segfault handler\n");
        exit(1);
    }
}

/*
 * Handle segmentation fault (page fault)
 */
static void segfault_handler(int sig, siginfo_t *si, void *unused) {
    void* fault_addr = si->si_addr;
    
    // Try to load the page containing the fault address
    if (load_page_for_address(fault_addr) != 0) {
        printf("Failed to handle page fault at address %p\n", fault_addr);
        exit(1);
    }
}

/*
 * Find the program header segment containing the given address
 */
static Elf32_Phdr* find_segment_for_address(uintptr_t addr) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD &&
            addr >= phdr[i].p_vaddr &&
            addr < (phdr[i].p_vaddr + phdr[i].p_memsz)) {
            return &phdr[i];
        }
    }
    return NULL;
}

/*
 * Load a single page for the given fault address
 */
static int load_page_for_address(void* fault_addr) {
    uintptr_t addr = (uintptr_t)fault_addr;
    Elf32_Phdr* segment = find_segment_for_address(addr);
    
    if (!segment) {
        return -1;
    }

    // Calculate page-aligned addresses
    uintptr_t page_start = addr & ~(PAGE_SIZE - 1);
    size_t segment_offset = page_start - segment->p_vaddr;
    size_t remaining_size = segment->p_memsz - segment_offset;
    size_t page_size = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

    // Map a single page
    void* mapped_addr = mmap((void*)page_start, PAGE_SIZE,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                            0, 0);
    
    if (mapped_addr == MAP_FAILED) {
        return -1;
    }

    // Read data from file into the mapped page
    if (segment_offset < segment->p_filesz) {
        size_t copy_size = MIN(page_size, segment->p_filesz - segment_offset);
        lseek(fd, segment->p_offset + segment_offset, SEEK_SET);
        read(fd, mapped_addr, copy_size);
    }

    total_page_faults++;
    total_page_allocations++;
    total_internal_fragmentation += (PAGE_SIZE - (remaining_size % PAGE_SIZE)) / 1024;  // Convert to KB

    return 0;
}

/*
 * Release memory and other cleanups
 */
void loader_cleanup() {
    // Print statistics
    printf("\nLoader Statistics:\n");
    printf("Total page faults: %d\n", total_page_faults);
    printf("Total page allocations: %d\n", total_page_allocations);
    printf("Total internal fragmentation: %d KB\n", total_internal_fragmentation);

    // Cleanup
    free(phdr);
    free(ehdr);
    free(elf_data);
    close(fd);
}

/*
 * Load and run the ELF executable file
 */
void load_and_run_elf(char** argv) {
    // Setup segfault handler for lazy loading
    setup_segfault_handler();
    
    // Open and read ELF file
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("Error opening the file\n");
        exit(1);
    }

    // Get file size
    elf_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Read ELF header
    ehdr = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    if (read(fd, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
        printf("Error reading ELF header\n");
        exit(1);
    }

    // Verify ELF magic number
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        printf("Not a valid ELF file\n");
        exit(1);
    }

    // Read program headers
    phdr = (Elf32_Phdr *)malloc(sizeof(Elf32_Phdr) * ehdr->e_phnum);
    lseek(fd, ehdr->e_phoff, SEEK_SET);
    if (read(fd, phdr, sizeof(Elf32_Phdr) * ehdr->e_phnum) != sizeof(Elf32_Phdr) * ehdr->e_phnum) {
        printf("Error reading program headers\n");
        exit(1);
    }

    // Get the entry point address
    void* entrypoint = (void*)(uintptr_t)ehdr->e_entry;

    // Cast entry point to function pointer and execute
    int (*_start)() = (int (*)())entrypoint;
    
    // This will trigger page faults which will be handled by our handler
    int result = _start();
    
    printf("User _start return value = %d\n", result);
}
