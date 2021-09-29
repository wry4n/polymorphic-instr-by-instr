/*-----------------------------------------------------------------------------------------------------------------------
 * A self-modifying program which uses ptrace to decrypt, execute and re-encrypt (with a different 
key) a function instruction by instruction
 * Payload: function which prints "Successfully running encrypted section"
 * Combining functionality from 
 *     (1) https://0x00sec.org/t/polycrypt-expiments-on-self-modifying-programs/857 and
 *     (2) https://0x00sec.org/t/ibi-crpter-a-jit-crypter-poc/1373
-----------------------------------------------------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>

#define PERROR(s) {perror(s); exit(1);}
#define FPRINT(s) {fprintf(stderr, s); exit(1);}

#define SECTION ".plt1" // new section which will be encrypted
#define INTO __attribute__((section(SECTION)))

#define KEY_SIZE 8
#define KEY_MASK 0x7

#define ENTRY_POINT ((unsigned char*)0x400000)

u_char key[KEY_SIZE + 1] ="\1\1\1\1\1\1\1\1"; // original key to "unencrypt" unencrypted code

typedef struct file_data_struct
{
    // encrypted section (in memory) 
    int    off; 
    int    len;

    // copy of binary file (on disk) 
    char   *fname;
    void   *code;
    int    code_len;

} FILE_DATA;

static int get_file_size (int fd)
{
    struct stat _info;
    fstat (fd, &_info);
    return _info.st_size;
}

Elf64_Shdr *find_section(void *map_addr, char *section_name) {

    Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *)map_addr;
    Elf64_Shdr *sec_hdr = (Elf64_Shdr *)(map_addr + elf_hdr->e_shoff);
    Elf64_Shdr *sec_hdr_str_tab = &sec_hdr[elf_hdr->e_shstrndx]; // section header string table index
    const char *const sec_hdr_str_tab_addr = map_addr + sec_hdr_str_tab->sh_offset;
    char *present_section_name;
    int i;

    for (i = 0; i < elf_hdr->e_shnum; i++)
    {
        present_section_name = (char*) (sec_hdr_str_tab_addr + sec_hdr[i].sh_name);
	if (!strcmp (present_section_name, section_name)) { 
	    return &sec_hdr[i];
	}
    }
    return NULL;
}

// function to be encrypted
INTO int encrypted_function (void)
{
    printf("[+] Successfully running encrypted section\n");
}

FILE_DATA* load (char *name)
{
    int fd;
    FILE_DATA *data;

    // allocate memory for and open file
    if ((data = malloc(sizeof(FILE_DATA))) == NULL) FPRINT("[!] malloc");
    if ((fd = open(name, O_RDONLY, 0)) < 0) PERROR("[!] open:");

    // struct: binary file name and code length
    data->fname = strdup (name);
    data->code_len = (get_file_size (fd));

    // allocate memory for and copy code 
    data->code = malloc (data->code_len);
    read (fd, data->code, data->code_len); 

    close(fd);
    return data;
}

void save (FILE_DATA *data)
{
    int fd;

    // delete original disk image
    if ((unlink(data->fname)) < 0) PERROR("[!] unlink:");

    // write re-encrypted (copy of) disk image
    if ((write((fd = open(data->fname, O_CREAT | O_TRUNC | O_RDWR,S_IRWXU)),
        data->code, data->code_len)) < 0) PERROR("[!] write:");

    close(fd);
    return;
}

void XOR (unsigned char *instr, u_char *given_key, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        instr[i] ^= (given_key[i & KEY_MASK] - 1);
    }
}

u_char *gen_new_key (u_char *key_cpy, int size)
{
    int i;
    for (i = 0; i < size; i++) key_cpy[i] = (rand() % 255);
    return key_cpy;
}

int change (FILE_DATA *data)
{
    /*
     * (1) get data section and key offset and 
     * (2) encrypted section offset and size
     */

    Elf64_Shdr *sec_hdr;
    int key_off;
    u_char *new_key;
												
    if ((sec_hdr = find_section (data->code, ".data")) == NULL) // find .data section (contained key offset)
        FPRINT("[!] .data not found\n");

    key_off = sec_hdr->sh_offset + 0x10; 																			
    if ((sec_hdr = find_section (data->code, SECTION)) == NULL) // find .plt1 section (containing ecrypted code)
        FPRINT("[!] encrypted section not found");

    data->off = sec_hdr->sh_offset; // struct: image encrypted section offset and size
    data->len = sec_hdr->sh_size;

    /*
     * mprotect
     */

    unsigned char *start = ENTRY_POINT + data->off;
    unsigned char *end = ENTRY_POINT + data->off + data->len;
    size_t pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t pagestart = (uintptr_t)start & -pagesize;
    int size = (end - (unsigned char*)pagestart);

    if (mprotect ((void*)pagestart, size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) PERROR("[!] mprotect:");

    /*
     * fork process
     */

    void *breakpoint;
    long rip, next_rip, instr1, instr2, instr1_cpy, instr2_cpy, stop;
    struct user_regs_struct regs;
    int status;
    pid_t _pid;

    if ((_pid = fork ()) < 0) PERROR("[!] fork:");						

    if (_pid == 0) return 0;  										
    else														
    {
        /*
	 * parent attaches to child process (and start debugging it)
	 */

        if ((ptrace (PTRACE_ATTACH, _pid, NULL, NULL)) < 0) PERROR ("[!] ptrace_attach:");
	wait (&status);	// wait for child to terminate
	printf ("[+] Attached to process\n");

        /*
         * setup debugger 
	 */

        breakpoint = ENTRY_POINT + data->off; // breakpoint 

        instr1 = ptrace (PTRACE_PEEKTEXT, _pid, breakpoint); // read word at breakpoint (copy it to instr1)
		
        if (ptrace (PTRACE_POKETEXT, _pid, breakpoint, // copy (set) breakpoint 
		   (instr1 & 0xFFFFFFFFFFFFFF00) | 0xcc) < 0) PERROR ("[!] ptrace_poke:");
            printf("[+] Breakpoint set at 0x%lx\n", breakpoint);

        if (ptrace (PTRACE_CONT, _pid, NULL, NULL) < 0) PERROR("[!] ptrace_cont:");
        wait(&status); // continue child process until breakpoint
	printf("[+] Continuing...\n");

	// decrememnt rip to orig. instr. replaced by interrupt  
	ptrace (PTRACE_GETREGS, _pid, NULL, &regs); // (a) copy child's general-purpose registers to &regs 
	printf("[+] Breakpoint reached (rip: 0c%llx)\n", regs.rip);  
      	regs.rip--;                                 // (b) decrememnt rip
	ptrace (PTRACE_SETREGS, _pid, 0, &regs);    // (c) reset registers
        ptrace (PTRACE_POKETEXT, _pid, breakpoint, instr1); // restore instructions

        /*
	 * generate key random new key
	 */

        new_key = gen_new_key ((u_char*)data->code + key_off, KEY_SIZE + 1);
	printf("[+] New key generated: 0x%lx\n", *(long *)new_key);

	/* 
	 * start debugger
	 */

        rip = (long) ENTRY_POINT + data->off; // set ip to beginning of memory image shell()
        unsigned char *cpy_ptr = data->code + data->off; // set cpy_ptr to beginning of disk image shell()
	printf("[+] Starting debugger...\n\n");		

        while (WIFSTOPPED(status)) // while WIFSTOPPED(status) == True
	{  		

	    /*
	     * unencrypt
	     */

	    instr1 = ptrace (PTRACE_PEEKTEXT, _pid, rip);			// Read 16 bytes (longest possible instruction)
	    instr2 = ptrace (PTRACE_PEEKTEXT, _pid, rip + 8);
	    printf("    rip: 0x%lx\n", rip);
	    printf("    encrypted:    %lx %lx\n", instr1, instr2);

	    XOR((unsigned char *)&instr1, key, 8);					// unencrypt bytes
	    XOR((unsigned char *)&instr2, key, 8);
	    printf("    unencrypted:  %lx %lx\n", instr1, instr2);

            ptrace (PTRACE_POKETEXT, _pid, rip, instr1);			// replace encrypted code with unencrypted code
            ptrace (PTRACE_POKETEXT, _pid, rip + 8, instr2);

            /*
	     * process instruction
	     */

            if (ptrace(PTRACE_SINGLESTEP, _pid, 0, 0) < 0) PERROR("[!] ptrace_singlestep:");
	    wait(&status);											// make child execute instruction 

            ptrace (PTRACE_GETREGS, _pid, 0, &regs);				// get new IP
	    next_rip = regs.rip;

            /*
	     * (a) re-encrypt: child process
	     */

            instr1_cpy = instr1;									// copy ops
	    instr2_cpy = instr2;

            XOR((unsigned char *)&instr1, key, 8);					// re-encrypt 16 bytes in child process
	    XOR((unsigned char *)&instr2, key, 8);

            ptrace (PTRACE_POKETEXT, _pid, rip, instr1);			// replace unenrypted code with encrypted code
	    ptrace (PTRACE_POKETEXT, _pid, rip + 8, instr2);
            //printf ("%lx :: OPCODES : %lx %lx\n", rip, instr1, instr2);
	    ////printf("\n");

            /*
	     * (b) re-encrypt: copy
	     */
																	// check if ip outside section
            if ((void*)next_rip < breakpoint || (void*)next_rip > breakpoint + data->len) {
                stop = (long)(breakpoint + data->len);
	    }
            else {
	        stop = next_rip;
            }

            XOR((unsigned char *)&instr1_cpy, new_key, stop-rip);	// re-encrypt code with new key
	    XOR((unsigned char *)&instr2_cpy, new_key, stop-rip-8);

            int i;													// replace unencrypted disk image with new encryption
	    for (i = 0; i < stop-rip; i++) {
                if (i < 8) {
                    cpy_ptr[i] = ((unsigned char *)&instr1_cpy)[i];
                }
                else {
                    cpy_ptr[i] = ((unsigned char *)&instr2_cpy)[i % 8];
                }
            }			
	
            printf("    re-encrypted: %lx %lx\n\n", instr1_cpy, instr2_cpy);

            /*
	     * final adjustments
	     */

            cpy_ptr += next_rip-rip;								// move copy ptr
            rip = next_rip;											// move ip ahead
                                                                                           // if code outside special section, break
            if ((void*)rip < breakpoint || (void*)rip > breakpoint + data->len)
	    {
	        break;
            }	
        }

        ptrace (PTRACE_CONT, _pid, 0, 0);
        wait (&status);      
    }

    if (mprotect ((void*)pagestart, size, PROT_READ | PROT_EXEC) < 0) PERROR("[!] mprotect:");
	
    // save (copy of) re-encrypted file to disk 
    save(data);
	
    exit(0);

}

int main (int argc, char *argv[])
{
    FILE_DATA *data;

    srand(time(NULL));

    data = load(argv[0]);

    change(data);

    encrypted_function();

    return 0;

}
