/* ======================================================================
       crashdmesg - VMCore Kernel Ring Buffer Dumper
       [ crashdmesg_elfutils.c ]
       Copyright(c) 2011 by Hiroshi KIHIRA.
   ====================================================================== */


/* --- Include header files --- */
#include "crashdmesg_common.h"


/* --- Prototypes --- */
static int elf_search_vmcoreinfo(VMCore *vmcore,
                                 off_t *offset, size_t *size);
static int elf_search_note_segment(VMCore *vmcore,
                                   off_t *offset, size_t *size);


/* ============================================================
       elf_validate_elfheader() - Read ELF header and Validate
   ============================================================ */
int elf_validate_elfheader(VMCore *vmcore)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_validate_elfheader:";
	uint8_t valid_ident[EI_NIDENT] = { 
	    ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
	    ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	Elf64_Ehdr *header = NULL;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(vmcore->file.fdesc != 0);
	
	header = &vmcore->elf_header;
	
	/* Read ident from file */
	if (file_read(&vmcore->file, (void*) header,
	              0, sizeof(Elf64_Ehdr))) {
		fprintf(stderr, "%s Can not read ELF header.\n", estr);
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
       elf_read_vmcoreinfo() - Read VMCOREINFO
   ============================================================ */
int elf_read_vmcoreinfo(VMCore *vmcore)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_vmcoreinfo:";
	off_t vmcoreinfo_offset = 0;
	size_t vmcoreinfo_size = 0;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(vmcore->elf_header.e_ident[0] == ELFMAG0);
	
	/* Search VMCOREINFO */
	if (elf_search_vmcoreinfo(vmcore, &vmcoreinfo_offset, &vmcoreinfo_size)) {
		fprintf(stderr, "%s Can not find VMCOREINFO data.\n", estr);
		return RETVAL_FAILURE;
	}
	
	/* Read VMCOREINFO */
	if (vmcoreinfo_size > sizeof(vmcore->vmcoreinfo)) {
		fprintf(stderr, "%s VMCOREINFO is too big.\n", estr);
		return RETVAL_FAILURE;
	}
	if (file_read(&vmcore->file, (void*) vmcore->vmcoreinfo,
	              vmcoreinfo_offset, vmcoreinfo_size)) {
		fprintf(stderr, "%s Failed to read VMCOREINFO.\n", estr);
		return RETVAL_FAILURE;
	}
	vmcore->vmcoreinfo_size = vmcoreinfo_size;
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_search_vmcoreinfo() - Search VMCOREINFO text
   ============================================================ */
static int elf_search_vmcoreinfo(VMCore *vmcore,
                                 off_t *offset, size_t *size)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_search_vmcoreinfo:";
	off_t note_offset = 0;
	size_t note_size = 0;
	Elf64_Nhdr note_header;
	memset(&note_header, 0x00, sizeof(Elf64_Nhdr));
	off_t cursor = 0;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(vmcore->vmcoreinfo[0] == 0x00);
	
	if (elf_search_note_segment(vmcore, &note_offset, &note_size)) {
		fprintf(stderr, "%s Can not find NOTE segment.\n", estr);
		return RETVAL_FAILURE;
	}
	
	/* Parse NOTE segment */
	for (cursor = note_offset; cursor < note_offset + note_size; ) {
		if (file_read(&vmcore->file, (void*) &note_header,
		              cursor, sizeof(Elf64_Nhdr))) {
			fprintf(stderr, "%s Failed to read NOTE header.\n", estr);
			return RETVAL_FAILURE;
		}
		if (note_header.n_type == NOTETYPE_VMCOREINFO) {
			/* VMCOREINFO found */
			*offset = cursor + sizeof(Elf64_Nhdr);
			*offset += ((note_header.n_namesz + 3) / 4) * 4;
			*size = note_header.n_descsz;
			if ((*size <= 0) ||
			    (*offset < note_offset) ||
			    (*offset >= note_offset + note_size) ||
			    (*offset + *size >= note_offset + note_size)) {
				fprintf(stderr, "%s VMCOREINFO found, but invalid.\n", estr);
				*offset = 0;
				*size = 0;
				return RETVAL_FAILURE;
			}
			return RETVAL_SUCCESS;
		}
		
		/* Skip segment */
		cursor += sizeof(Elf64_Nhdr);
		cursor += ((note_header.n_namesz + 3) / 4) * 4;
		cursor += ((note_header.n_descsz + 3) / 4) * 4;
	}

	/* VMCOREINFO not found */
	fprintf(stderr, "%s VMCOREINFO not found.\n", estr);
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_search_note_segment() - Search NOTE segment
   ============================================================ */
static int elf_search_note_segment(VMCore *vmcore,
                                   off_t *offset, size_t *size)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_search_note_segment:";
	Elf64_Phdr pgm_header;
	memset(&pgm_header, 0x00, sizeof(Elf64_Phdr));
	off_t ph_offset = 0;
	int loop = 0;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(offset != NULL);
	assert(size != NULL);
	
	ph_offset = vmcore->elf_header.e_phoff;
	for (loop = 0; loop < vmcore->elf_header.e_phnum; loop++) {
		if (file_read(&vmcore->file, (void*) &pgm_header,
		              ph_offset, sizeof(Elf64_Phdr))) {
			fprintf(stderr, "%s Failed to read program header.\n", estr);
			return RETVAL_FAILURE;
		}
		if (pgm_header.p_type == PT_NOTE) {
			/* NOTE segment found */
			*offset = pgm_header.p_offset;
			*size = pgm_header.p_filesz;
			if ((*offset < 0) || (*size <= 0) ||
			    (*offset >= vmcore->file.size) ||
			    (*offset + *size >= vmcore->file.size)) {
				fprintf(stderr, "%s NOTE segment found, but invalid.\n", estr);
				*offset = 0;
				*size = 0;
				return RETVAL_FAILURE;
			}
			return RETVAL_SUCCESS;
		}
		ph_offset += vmcore->elf_header.e_phentsize;
	}
	
	/* NOTE segment not found */
	fprintf(stderr, "%s NOTE segment not found.\n", estr);
	return RETVAL_FAILURE;
}


/* ============================================================
       elf_search_vmcoreinfo_symbol() - Return Symbol value
   ============================================================ */
int elf_search_vmcoreinfo_symbol(VMCore *vmcore, char *key, uint64_t *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_search_vmcoreinfo_symbol:";
	int key_length = 0;
	char search_key[MAX_SYMBOL_NAME];
	memset(search_key, 0x00, sizeof(search_key));
	char addrtext[17];
	memset(addrtext, 0x00, sizeof(addrtext));
	char *cursor = 0;
	char *limit = 0;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(ret != NULL);
	
	/* Build search key */
	key_length = strlen(key);
	cursor = search_key;
	if (key_length + 9 >= sizeof(search_key)) {
		fprintf(stderr, "%s Search key \"%s\" is too big.\n", estr, key);
		return RETVAL_FAILURE;
	}
	memcpy(cursor, "SYMBOL(", 7);
	cursor += 7;
	memcpy(cursor, key, key_length);
	cursor += key_length;
	memcpy(cursor, ")=", 2);
	*(cursor + 2) = 0x00;
	
	/* Search "SYMBOL(key)=" */
	if (elf_search_vmcoreinfo_key(vmcore, search_key, &cursor)) {
		fprintf(stderr, "%s Failed to serarch \"%s\" in VMCOREINFO",
		        estr, search_key);
		return RETVAL_FAILURE;
	}
	
	/* Read value */
	limit = vmcore->vmcoreinfo + vmcore->vmcoreinfo_size;
	cursor += strlen(search_key);
	if (cursor + sizeof(addrtext) >= limit) {
		fprintf(stderr, "%s Can not read value.\n", estr);
		return RETVAL_FAILURE;
	}
	memcpy(addrtext, cursor, sizeof(addrtext));
	if (addrtext[16] != 0x00) {
		if (addrtext[16] == '\n') {
			addrtext[16] = 0x00;
		}
		else {
			/* Invalid text */
			fprintf(stderr, "%s Can not read value.\n", estr);
			return RETVAL_FAILURE;
		}
	}
	
	/* Convert text to addr */
	*ret = strtoull(addrtext, NULL, 16);
	if (*ret == 0) {
		fprintf(stderr, "%s Failed to convert value.\n", estr);
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_search_vmcoreinfo_key() - Search and return offset
   ============================================================ */
int elf_search_vmcoreinfo_key(VMCore *vmcore, char *key, char* *ptr)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_search_vmcoreinfo_symbol:";
	int key_length = 0;
	char *cursor = NULL;
	char *limit = NULL;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(key != NULL);
	assert(ptr != NULL);
	
	key_length = strlen(key);
	limit = vmcore->vmcoreinfo + vmcore->vmcoreinfo_size;
	for (cursor = vmcore->vmcoreinfo; cursor <  limit; cursor++) {
		if (*cursor == key[0]) {
			if (cursor + key_length < limit) {
				if (! memcmp(cursor, key, key_length)) {
					*ptr = cursor;
					return RETVAL_SUCCESS;
				}
			}
			else {
				/* Nearly end of buffer */
				goto ERROR_NOTFOUND;
			}
		}
	}
	
ERROR_NOTFOUND:
	/* key not found */
	fprintf(stderr, "%s Key(%s) not found in VMCOREINFO.\n", estr, key);
	return RETVAL_FAILURE;
}


/* ============================================================
       elf_read_load_uint64() - Read uint64_t value from LOAD
   ============================================================ */
int elf_read_load_uint64(VMCore *vmcore, Elf64_Phdr *phdr_cache,
                         uint64_t vaddr, uint64_t *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_load_uint64:";
	off_t ret_offset = 0;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(phdr_cache != NULL);
	
	/* Search and Read */
	if (elf_search_load_data(vmcore, phdr_cache,
	                         vaddr, sizeof(uint64_t), &ret_offset)) {
		fprintf(stderr, "%s Can not find data.\n", estr);
		return RETVAL_FAILURE;
	}
	if (file_read(&vmcore->file, (void*) ret, ret_offset, sizeof(uint64_t))) {
		fprintf(stderr, "%s Can not read data from file.\n", estr);
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_read_load_uint32() - Read uint32_t value from LOAD
   ============================================================ */
int elf_read_load_uint32(VMCore *vmcore, Elf64_Phdr *phdr_cache,
                         uint64_t vaddr, uint32_t *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_load_uint32:";
	off_t ret_offset = 0;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(phdr_cache != NULL);
	
	/* Search and Read */
	if (elf_search_load_data(vmcore, phdr_cache,
	                         vaddr, sizeof(uint32_t), &ret_offset)) {
		fprintf(stderr, "%s Can not find data.\n", estr);
		return RETVAL_FAILURE;
	}
	if (file_read(&vmcore->file, (void*) ret, ret_offset, sizeof(uint32_t))) {
		fprintf(stderr, "%s Can not read data from file.\n", estr);
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_read_load_int32() - Read int32_t value from LOAD
   ============================================================ */
int elf_read_load_int32(VMCore *vmcore, Elf64_Phdr *phdr_cache,
                        uint64_t vaddr, int32_t *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_load_int32:";
	off_t ret_offset = 0;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(phdr_cache != NULL);
	
	/* Search and Read */
	if (elf_search_load_data(vmcore, phdr_cache,
	                         vaddr, sizeof(int32_t), &ret_offset)) {
		fprintf(stderr, "%s Can not find data.\n", estr);
		return RETVAL_FAILURE;
	}
	if (file_read(&vmcore->file, (void*) ret, ret_offset, sizeof(int32_t))) {
		fprintf(stderr, "%s Can not read data from file.\n", estr);
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       elf_search_load_data() - Search data and return file offset
   ============================================================ */
int elf_search_load_data(VMCore *vmcore, Elf64_Phdr *phdr_cache,
                         uint64_t vaddr, size_t size, off_t *ret)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] elf_read_load_uin64:";
	off_t ph_offset = 0;
	int loop = 0;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	assert(phdr_cache != NULL);
	assert(ret != NULL);
	assert(size > 0);
	
	/* Search LOAD segment, use cache first */
	if ((phdr_cache->p_type == PT_LOAD) && (phdr_cache->p_offset > 0) &&
	    (phdr_cache->p_vaddr > 0) && (phdr_cache->p_filesz > 0)) {
		/* Program header cache is valid */
		if ((vaddr >= phdr_cache->p_vaddr) &&
		    (vaddr + size < phdr_cache->p_vaddr + phdr_cache->p_filesz)) {
			/* return data offset in file */
			*ret = phdr_cache->p_offset + vaddr - phdr_cache->p_vaddr;
			return RETVAL_SUCCESS;
		}
	}
	
	/* Search each LOAD segment */
	ph_offset = vmcore->elf_header.e_phoff;
	for (loop = 0; loop < vmcore->elf_header.e_phnum; loop++) {
		if (file_read(&vmcore->file, (void*) phdr_cache,
		    ph_offset, sizeof(Elf64_Phdr))) {
			fprintf(stderr, "%s Failed to read program header.\n", estr);
			return RETVAL_FAILURE;
		}
		if (phdr_cache->p_type == PT_LOAD) {
			/* LOAD segment found */
			if ((vaddr >= phdr_cache->p_vaddr) &&
			    (vaddr + size < phdr_cache->p_vaddr + phdr_cache->p_filesz)) {
				*ret = phdr_cache->p_offset + vaddr - phdr_cache->p_vaddr;
				return RETVAL_SUCCESS;
			}
		}
		ph_offset += vmcore->elf_header.e_phentsize;
	}
	
	/* LOAD segment not found */
	fprintf(stderr, "%s Data not found in LOAD segment.\n", estr);
	return RETVAL_FAILURE;
}


/* ====================================================================== */
