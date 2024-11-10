# OS-Assignment-4-SimpleSmartLoader


Group ID- 58


Group Members:


Bhuvika Mehta (bhuvika23172@iiitd.ac.in)


Pragya Singh (pragya23379@iiitd.ac.in)


Github Repository link- (https://github.com/bhuvikamehta/OS-Assignment-4-SimpleSmartLoader)


Contribution:
Both contributed equally and were present at all times. The task was distributed equally within both members.

Implementation:
This simple smart loader reads and verifies the ELF file, locating executable sections and entry points. The code also includes a signal handler for segmentation faults, which handles memory mapping and execution issues.  It catches page faults, maps required pages, and loads data dynamically. sigaction() sets up a signal handler for segmentation faults (SIGSEGV), which triggers segfault_handler() whenever a page fault occurs. When the program attempts to access unmapped memory, segfault_handler() allocates the required pages on demand, mapping only as much memory as needed. It also prints number of page faults, allocated pages and total amount of internal fragmentation in kB. 
To use this loader, compile and run the code using:
make
./loader ./<file name>




