/* ======================================================================
       crashdmesg - VMCore Kernel Ring Buffer Dumper
       [ crashdmesg_elfutils.c ]
       Copyright(c) 2011 by Hiroshi KIHIRA.
   ====================================================================== */


/* --- Include header files --- */
#include "crashdmesg_common.h"


/* --- Prototypes --- */
static int elf_parse_vmcoreinfo(uint8_t *cursor, uint8_t *limit,
                                char *key, uint64_t *res);


/* ============================================================
       elf_validate_header() - Read ELF header and Validate
   ============================================================ */
int elf_validate_header(File *file, Elf64_Ehdr *header)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_validate_header:";
	uint8_t valid_ident[EI_NIDENT] = {
	    ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
	    ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(header != NULL);
	
	/* Read ident from file */
	if (file_read(file, (void*) header, 0, sizeof(Elf64_Ehdr))) {
		fprintf(stderr, "%s Can not read ELF header from file.\n", estr);
		return RETVAL_FAILURE;
	}
	
	/* Validate IDENT (first 16byte) */
	if (memcmp((void*) header->e_ident, (void*) valid_ident, EI_NIDENT)) {
		fprintf(stderr, "%s Invalid IDENT data.\n", estr);
		return RETVAL_FAILURE;
	}
	
	/* Validate remaining header */
	if ( (header->e_type != ET_CORE) || (header->e_machine != EM_X86_64) ||
	     (header->e_version != EV_CURRENT ) || (header->e_entry != 0x00) ||
	     (header->e_phoff == 0) || (header->e_phentsize != sizeof(Elf64_Phdr)) ||
	     (header->e_phnum == 0) ) {
		fprintf(stderr, "%s Invalid ELF header or Not ELF Core file.\n", estr);
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_mmap_vmcore() - Mmap VMCore file
   ============================================================ */
int elf_mmap_vmcore(File *file, uint8_t* *buffer)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_mmap_vmcore:";
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	
	if (file_mmap(file, (void**)buffer, 0, file->size)) {
		fprintf(stderr, "%s Can not mmap input file.\n", estr);
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_munmap_vmcore() - Munmap VMCore file
   ============================================================ */
int elf_munmap_vmcore(File *file, uint8_t* *buffer)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_munmap_vmcore:";
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	
	if (file_munmap((void**)buffer, file->size)) {
		fprintf(stderr, "%s Can not munmap input file.\n", estr);
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_search_note_section() - Search NOTE section
   ============================================================ */
int elf_search_note_section(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                            uint8_t* *note, size_t *size)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_search_note_section:";
	uint16_t loop = 0;
	Elf64_Phdr *phlist = NULL;
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	assert(header != NULL);
	assert(note != NULL);
	assert(size != NULL);
	
	phlist = (Elf64_Phdr*) (buffer + header->e_phoff);
	
	/* Check buffer overflow */
	if ((header->e_phoff > file->size) || (header->e_phoff +
	     sizeof(Elf64_Phdr) * header->e_phnum > file->size)) {
		fprintf(stderr, "%s Invalid program header size.\n", estr);
		return RETVAL_FAILURE;
	}
	
	/* Search NOTE section */
	for (loop = 0; loop < header->e_phnum; loop++) {
		if (phlist[loop].p_type == PT_NOTE) {
			/* NOTE section found */
			if ( (phlist[loop].p_offset > file->size) ||
			     (phlist[loop].p_offset + phlist[loop].p_filesz > file->size)) {
				fprintf(stderr, "%s NOTE section found, but Invalid.\n", estr);
				return RETVAL_FAILURE;
			}
			*note = buffer + phlist[loop].p_offset; /* "*note" is NOT offset */
			*size = phlist[loop].p_filesz;
			return RETVAL_SUCCESS;
		}
	}
	fprintf(stderr, "%s NOTE section not found.\n", estr);
	return RETVAL_FAILURE;
}


/* ============================================================
       elf_search_vmcoreinfo() - Search Symbol address
   ============================================================ */
int elf_search_vmcoreinfo(uint8_t *note, size_t size, char *key, uint64_t *res)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_unmap_note_section:";
	uint8_t *cursor = NULL;
	uint8_t *limit = NULL;
	
	/* --- Assert check --- */
	assert(note != NULL);
	assert(size > 0);
	assert(key != NULL);
	assert(res != NULL);
	
	/* Search "SYMBOL" */
	limit = note + size;
	for (cursor = note; cursor < limit; cursor++) {
		if (*cursor == 'S') {
			if (cursor + 6 < limit) {
				if (! memcmp(cursor, "SYMBOL", 6)) {
					if (! elf_parse_vmcoreinfo(cursor, limit, key, res)) {
						/* "SYMBOL(key)" found */
						return RETVAL_SUCCESS;
					}
				}
			}
			else {
				/* Nearly end of buffer */
				fprintf(stderr, "%s Symbol(%s) not found.\n", estr, key);
				return RETVAL_FAILURE;
			}
		}
	}
	/* "SYMBOL" not found */
	fprintf(stderr, "%s Symbol(%s) not found.\n", estr, key);
	return RETVAL_FAILURE;
}


/* ============================================================
       elf_parse_vmcoreinfo() - Parse text "SYMBOL(key)=addr\n"
   ============================================================ */
static int elf_parse_vmcoreinfo(uint8_t *cursor, uint8_t *limit,
                                char *key, uint64_t *res)
{
	/* --- Variables --- */
	size_t keysize = 0;
	char buffer[17];
	memset(buffer, 0x00, sizeof(buffer));
	
	/* --- Assert check --- */
	assert(cursor != NULL);
	assert(limit > cursor);
	assert(key != NULL);
	assert(res != NULL);
	
	keysize = strlen(key);
	cursor += 7; /* "SYMBOL(" */
	if (cursor + keysize + 2 >= limit) {
		/* Can not search key */
		return RETVAL_FAILURE;
	}
	if (memcmp(cursor, key, keysize) || memcmp(cursor + keysize, ")=", 2)) {
		/* Not match key */
		return RETVAL_FAILURE;
	}
	
	/* key found and parse address */
	cursor += keysize + 2; /* skip key and ")=" */
	if (cursor + 16 >= limit) {
		/* No space for address */
		return RETVAL_FAILURE;
	}
	
	/* Copy address text to buffer */
	memcpy(buffer, cursor, 17);
	if (buffer[16] != 0x00) {
		if (buffer[16] == '\n') {
			buffer[16] = 0x00;
		}
		else {
			/* Invalid text */
			return RETVAL_FAILURE;
		}
	}
	
	/* Convert text to addr */
	*res = strtoull(buffer, NULL, 16);
	if (*res == 0) {
		/* strtoull failed */
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_read_uint64_from_load() - Read uint64_t value
   ============================================================ */
int elf_read_uint64_from_load(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                              uint64_t vaddr, uint64_t *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_uint64_from_load:";
	uint64_t *value = 0;
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	assert(header != NULL);
	assert(ret != NULL);
	assert(vaddr > 0);
	
	if (elf_read_load_section(file, buffer, header, vaddr,
	                          8, (uint8_t**) &value)) {
		fprintf(stderr, "%s Can not read value.\n", estr);
		return RETVAL_FAILURE;
	}
	
	*ret = *value;
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_read_uint32_from_load() - Read uint32_t value
   ============================================================ */
int elf_read_uint32_from_load(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                              uint64_t vaddr, uint32_t *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_uint64_from_load:";
	uint32_t *value = 0;
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	assert(header != NULL);
	assert(ret != NULL);
	assert(vaddr > 0);
	
	if (elf_read_load_section(file, buffer, header, vaddr,
	                          4, (uint8_t**) &value)) {
		fprintf(stderr, "%s Can not read value.\n", estr);
		return RETVAL_FAILURE;
	}
	
	*ret = *value;
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_read_int32_from_load() - Read int32_t value
   ============================================================ */
int elf_read_int32_from_load(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                              uint64_t vaddr, int32_t *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_uint64_from_load:";
	int32_t *value = NULL;
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	assert(header != NULL);
	assert(ret != NULL);
	assert(vaddr > 0);
	
	if (elf_read_load_section(file, buffer, header, vaddr,
	                          4, (uint8_t**) &value)) {
		fprintf(stderr, "%s Can not read value.\n", estr);
		return RETVAL_FAILURE;
	}
	
	*ret = *value;
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_read_load_section() - Read LOAD section
   ============================================================ */
int elf_read_load_section(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                          uint64_t vaddr, size_t size, uint8_t* *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_load_section:";
	uint16_t loop = 0;
	Elf64_Phdr *phlist = NULL;
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	assert(header != NULL);
	assert(ret != NULL);
	assert(vaddr > 0);
	assert(size > 0);
	
	phlist = (Elf64_Phdr*) (buffer + header->e_phoff);
	
	/* Check buffer overflow */
	if ((header->e_phoff > file->size) || (header->e_phoff +
	     sizeof(Elf64_Phdr) * header->e_phnum > file->size)) {
		fprintf(stderr, "%s Invalid program header size.\n", estr);
		return RETVAL_FAILURE;
	}
	
	/* Search LOAD section */
	for (loop = 0; loop < header->e_phnum; loop++) {
		if (phlist[loop].p_type == PT_LOAD) {
			/* LOAD section found */
			if ( (phlist[loop].p_offset > file->size) ||
			     (phlist[loop].p_offset + phlist[loop].p_filesz > file->size)) {
				fprintf(stderr, "%s LOAD section found, but Invalid.\n", estr);
				return RETVAL_FAILURE;
			}
			
			if ( (vaddr >= phlist[loop].p_vaddr) &&
			     (vaddr < phlist[loop].p_vaddr + phlist[loop].p_filesz) &&
			     (vaddr + size >= phlist[loop].p_vaddr) &&
			     (vaddr + size < phlist[loop].p_vaddr +
			                     phlist[loop].p_filesz) ) {
				/* phlist[loop] contain target data */
				*ret = (uint8_t*) buffer + phlist[loop].p_offset +
				       vaddr - phlist[loop].p_vaddr;
				return RETVAL_SUCCESS;
			}
		}
	}
	fprintf(stderr, "%s LOAD section not found.\n", estr);
	return RETVAL_FAILURE;
}


/* ====================================================================== */
