#include <fcntl.h>
#include <stdlib.h>
#include <elf.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#define PAGE_SIZE	4096
#define ALIGN		(PAGE_SIZE - 1)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR	((unsigned long)-1)

static int check_ehdr(Elf64_Ehdr *ehdr) {
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
	    	e_ident[EI_CLASS] != ELFCLASS64 ||
		e_ident[EI_VERSION] != EV_CURRENT ||
		(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)) ? 0 : 1;
}

static unsigned long loadelf_anon(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr)
{
	unsigned long minva, maxva;
	Elf64_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;

	minva = (unsigned long)-1;
	maxva = 0;
	
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	/* For dynamic ELF let the kernel chose the address. */	
	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	/* Check that we can hold the whole image. */
	base = mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return -1;
	munmap(base, maxva - minva);

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		p = mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
		if (p == (void *)-1)
			goto err;
		if (lseek(fd, iter->p_offset, SEEK_SET) < 0)
			goto err;
        printf("%p\n", p + off);
		if (read(fd, p + off, iter->p_filesz) !=
				(ssize_t)iter->p_filesz)
			goto err;
		mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	munmap(base, maxva - minva);
	return LOAD_ERR;
}

void trampoline(void*, void*, void*);

static void fini(void) {
}

int main(int host_argc, char* host_argv[], char* host_envp[]) {
    char* file = "test/a.out";
    int fd;
    if ((fd = open(file, O_RDONLY)) < 0) {
        printf("could not open file\n");
        exit(1);
    }

    Elf64_Ehdr ehdrs, *ehdr = &ehdrs;
    if (read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr)) {
        printf("can't read ELF header\n");
        exit(1);
    }
    if (!check_ehdr(ehdr)) {
        printf("bad ELF header\n");
        exit(1);
    }

    ssize_t sz = ehdr->e_phnum * sizeof(Elf64_Phdr);
    Elf64_Phdr* phdr = malloc(sz);
    if (lseek(fd, ehdr->e_phoff, SEEK_SET) < 0) {
        printf("seek to program header failed\n");
        exit(1);
    }
    if (read(fd, phdr, sz) != sz) {
        printf("read program header failed\n");
        exit(1);
    }
    unsigned long base, entry;
    if ((base = loadelf_anon(fd, ehdr, phdr)) == LOAD_ERR) {
        printf("can't load ELF file\n");
        exit(1);
    }

    entry = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base : 0);

    close(fd);

    void *sp_base = calloc(1, 1 << 21);
    unsigned long *sp = sp_base + (1 << 21) - 128;

    (*sp)++;
    int argc = (int)*(sp);
	char **argv = (char **)(sp + 1);
    argv[0] = "a.out";
    char **env, **p;
	env = p = (char **)&argv[argc + 1];
	while (*p++ != NULL)
		;
    while (*host_envp++ != NULL);
    Elf64_auxv_t *av = (void *)p;
    Elf64_auxv_t *host_av = (void *)host_envp;

    /* Reassign some vectors that are important for
	 * the dynamic linker and for lib C. */
#define AVSET(t, v, expr) case (t): (v)->a_un.a_val = (expr); break
	while (host_av->a_type != AT_NULL) {
        *av = *host_av;
		switch (av->a_type) {
		AVSET(AT_PHDR, av, base + ehdrs.e_phoff);
		AVSET(AT_PHNUM, av, ehdrs.e_phnum);
		AVSET(AT_PHENT, av, ehdrs.e_phentsize);
		AVSET(AT_ENTRY, av, entry);
		AVSET(AT_EXECFN, av, (unsigned long)argv[0]);
		AVSET(AT_BASE, av, av->a_un.a_val);
		}
		++av;
        ++host_av;
	}
#undef AVSET
	++av;

    trampoline((void*) entry, sp, fini);

    return 0;
}