/* ======================================================================
       crashdmesg - VMCore Kernel Ring Buffer Dumper
       [ crashdmesg_main.c ]
       Copyright(c) 2011 by Hiroshi KIHIRA.
   ====================================================================== */


/* --- Include header files --- */
#include "crashdmesg_common.h"


/* --- Prototypes --- */
static void print_usage(void);
static int parse_option(int argc, char *argv[], File *file);
static int crashdmesg(File *file);


/* ============================================================
       main() - MAIN
   ============================================================ */
int main(int argc, char *argv[])
{
	/* --- Variables --- */
	char estr[] = "[ERROR] main:";
	File file;
	memset(&file, 0x00, sizeof(File));
	
	fprintf(stdout, "%s:  %s start.\n", APP_NAME, APP_NAME);
	
	/* Check args */
	if (parse_option(argc, argv, &file)) {
		fprintf(stderr, "%s Invalid option.\n", estr);
		print_usage();
		return RETVAL_FAILURE;
	}
	fprintf(stdout, "%s:   Target file: %s\n", APP_NAME, file.filename);
	
	/* Do crashdmesg */
	if (crashdmesg(&file)) {
		fprintf(stderr, "%s Dump Failed.\n", estr);
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       print_usage() - Print command usage to Stdout
   ============================================================ */
static void print_usage(void)
{
	fprintf(stdout, "%s (%s) - %s\n\n", APP_NAME, APP_FULLNAME, APP_VERSION);
	fprintf(stdout, "Usage:  %s [vmcore]\n", APP_NAME);
	fprintf(stdout, " vmcore        VMCore file to dump. [/proc/vmcore]\n");
	return;
}


/* ============================================================
       parse_option() - Parse and validate commandline option
   ============================================================ */
static int parse_option(int argc, char *argv[], File *file)
{
	/* --- Assert check --- */
	assert(argv != NULL);
	assert(file != NULL);
	
	if (argc == 2) {
		file->filename = argv[1];
	}
	else if (argc == 1) {
		file->filename = DEFAULT_VMCORE;
	}
	else {
		/* Invalid option num */
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       crashdmesg() - Ring buffer dumper Core routine
   ============================================================ */
static int crashdmesg(File *file)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] crashdmesg:";
	Elf64_Ehdr elf_header;
	memset(&elf_header, 0x00, sizeof(Elf64_Ehdr));
	uint8_t *buffer = NULL;
	uint8_t *note = NULL;
	size_t size = 0;
	int loop = 0;
	
	/* Ring buffer data */
	uint64_t log_buf_addr = 0; /* virtual address of data */
	uint64_t log_buf = 0; /* Pointer of "__log_buf" */
	uint64_t log_end_addr = 0; /* virtual address of data */
	uint32_t log_end = 0; /* unsigned int value */
	uint64_t log_buf_len_addr = 0; /* virtual address of data */
	int32_t log_buf_len = 0; /* signed int value */
	uint64_t logged_chars_addr = 0; /* virtual address of data */
	uint32_t logged_chars = 0;  /* unsigned int value */
	
	/* Pointer of ring buffer */
	uint8_t *ringbuffer1 = NULL;
	uint32_t ringbuffer1_size = 0;
	uint8_t *ringbuffer2 = NULL;
	uint32_t ringbuffer2_size = 0;
	
	/* --- Assert check --- */
	assert(file != NULL);
	
	/* Open VMcore and validate */
	fprintf(stdout, "%s:  Validate vmcore ELF binary header.\n", APP_NAME);
	if (file_open(file)) {
		fprintf(stderr, "%s Failed to open VMcore: %s\n", estr, file->filename);
		return RETVAL_FAILURE;
	}
	if (elf_validate_header(file, &elf_header)) {
		fprintf(stderr, "%s Invalid VMcore: %s\n", estr, file->filename);
		goto ERROR_CLOSE;
	}
	if (elf_mmap_vmcore(file, &buffer)) {
		fprintf(stderr, "%s Failed to mmap VMcore.\n", estr);
		goto ERROR_CLOSE;
	}
	
	/* Search and check NOTE section */
	fprintf(stdout, "%s:  Search NOTE section.\n", APP_NAME);
	if (elf_search_note_section(file, buffer, &elf_header, &note, &size)) {
		fprintf(stderr, "%s Failed to search NOTE section.\n", estr);
		goto ERROR_MUNMAP;
	}
	
	/* Search ring buffer data */
	fprintf(stdout, "%s:  Search Symbol about ring buffer.\n", APP_NAME);
	if ( elf_search_vmcoreinfo(note, size, "log_buf", &log_buf_addr) ||
	     elf_search_vmcoreinfo(note, size, "log_end", &log_end_addr) ||
	     elf_search_vmcoreinfo(note, size, "log_buf_len", &log_buf_len_addr) ||
	     elf_search_vmcoreinfo(note, size, "logged_chars", &logged_chars_addr)
	   ) {
		fprintf(stderr, "%s Failed to get address from vmcoreinfo.\n", estr);
		goto ERROR_MUNMAP;
	}
	fprintf(stdout, "%s:    * log_buf:      0x%016lx\n",
	        APP_NAME, log_buf_addr);
	fprintf(stdout, "%s:    * log_end:      0x%016lx\n",
	        APP_NAME, log_end_addr);
	fprintf(stdout, "%s:    * log_buf_len:  0x%016lx\n",
	        APP_NAME, log_buf_len_addr);
	fprintf(stdout, "%s:    * logged_chars: 0x%016lx\n",
	        APP_NAME, logged_chars_addr);
	
	/* Read log_buf address, size, etc. */
	fprintf(stdout, "%s:  Read LOAD section containing Ring buffer.\n", APP_NAME);
	if ( elf_read_uint64_from_load(file, buffer, &elf_header,
	                               log_buf_addr, &log_buf) ||
	     elf_read_uint32_from_load(file, buffer, &elf_header,
	                               log_end_addr, &log_end) ||
	     elf_read_int32_from_load(file, buffer, &elf_header,
	                              log_buf_len_addr, &log_buf_len) ||
	     elf_read_uint32_from_load(file, buffer, &elf_header,
	                               logged_chars_addr, &logged_chars) ) {
		fprintf(stderr, "%s Failed to get value from vmcoreinfo.\n", estr);
		goto ERROR_MUNMAP;
	}
	fprintf(stdout, "%s:    * log_buf:      0x%016lx\n",
	        APP_NAME, log_buf);
	fprintf(stdout, "%s:    * log_end:              0x%08x\n",
	        APP_NAME, log_end);
	fprintf(stdout, "%s:    * log_buf_len:          0x%08x\n",
	        APP_NAME, log_buf_len);
	fprintf(stdout, "%s:    * logged_chars:         0x%08x\n",
	        APP_NAME, logged_chars);
	
	/* Check log_buf size for safety */
	if (log_buf_len > MAX_LOGBUF_LIMIT) {
		fprintf(stderr, "%s log_buf_len is too big.\n", estr);
		goto ERROR_MUNMAP;
	}

	/* Calc. Dump address */
	fprintf(stdout, "%s:  Calculating dump area address.\n", APP_NAME);
	if ( logged_chars < log_buf_len ) {
		/* ring buffer not filled */
		ringbuffer1_size = logged_chars;
		if (elf_read_load_section(file, buffer, &elf_header,
                                  log_buf, ringbuffer1_size, &ringbuffer1)) {
			fprintf(stderr, "%s Ring buffer not found in vmcore.\n", estr);
			goto ERROR_MUNMAP;
		}
		fprintf(stdout, "%s:   Ring buffer Part: 1/1\n", APP_NAME);
		fprintf(stdout, "%s:    * File Offset:  0x%016lx\n",
		        APP_NAME, ringbuffer1 - buffer);
		fprintf(stdout, "%s:    * Size:                 0x%08x\n",
		        APP_NAME, ringbuffer1_size);
		/* DUMP */
		fprintf(stdout, "%s:  Dump ring buffer.\n", APP_NAME);
		fprintf(stdout,
		        ">>>>>>>>>>[ START kernel ring buffer ]>>>>>>>>>>>>>>>>>\n");
		for (loop = 0; loop < ringbuffer1_size; loop++) {
			fputc(ringbuffer1[loop], stdout);
		}
		fprintf(stdout,
		        "<<<<<<<<<<[ END kernel ring buffer   ]<<<<<<<<<<<<<<<<<\n");
	}
	else {
		/* ring buffer filled  */
		ringbuffer1_size = log_buf_len - (log_end & (log_buf_len-1));
		ringbuffer2_size = log_end & (log_buf_len-1);
		if ( ((ringbuffer1_size + ringbuffer2_size) != log_buf_len) ||
		     ((ringbuffer1_size + ringbuffer2_size) > MAX_LOGBUF_LIMIT) ) {
			fprintf(stderr, "%s Dump area size calculation failed.\n", estr);
			goto ERROR_MUNMAP;
		}
		if (elf_read_load_section(file, buffer, &elf_header,
		                          log_buf + (log_end & (log_buf_len-1)),
		                          ringbuffer1_size, &ringbuffer1) ||
		    elf_read_load_section(file, buffer, &elf_header, log_buf,
		                          ringbuffer2_size, &ringbuffer2)) {
			fprintf(stderr, "%s Ring buffer not found in vmcore.\n", estr);
			goto ERROR_MUNMAP;
		}
		fprintf(stdout, "%s:   Ring buffer Part: 1/2\n", APP_NAME);
		fprintf(stdout, "%s:    * File Offset:  0x%016lx\n",
		        APP_NAME, ringbuffer1 - buffer);
		fprintf(stdout, "%s:    * Size:                 0x%08x\n",
		        APP_NAME, ringbuffer1_size);
		fprintf(stdout, "%s:   Ring buffer Part: 2/2\n", APP_NAME);
		fprintf(stdout, "%s:    * File Offset:  0x%016lx\n",
		        APP_NAME, ringbuffer2 - buffer);
		fprintf(stdout, "%s:    * Size:                 0x%08x\n",
		        APP_NAME, ringbuffer2_size);
		/* DUMP */
		fprintf(stdout, "%s:  Dump ring buffer.\n", APP_NAME);
		fprintf(stdout,
		        ">>>>>>>>>>[ START kernel ring buffer ]>>>>>>>>>>>>>>>>>\n");
		for (loop = 0; loop < ringbuffer1_size; loop++) {
			fputc(ringbuffer1[loop], stdout);
		}
		for (loop = 0; loop < ringbuffer2_size; loop++) {
			fputc(ringbuffer2[loop], stdout);
		}
		fprintf(stdout,
		        "<<<<<<<<<<[ END kernel ring buffer   ]<<<<<<<<<<<<<<<<<\n");
	}
	
	fprintf(stdout, "%s: Dump complete.\n", APP_NAME);
	
	/* Munmap and close file */
	elf_munmap_vmcore(file, &buffer);
	file_close(file);
	
	return RETVAL_SUCCESS;
	
	/* Error */
ERROR_MUNMAP:
	elf_munmap_vmcore(file, &buffer);
ERROR_CLOSE:
	file_close(file);
	
	return RETVAL_FAILURE;
}

/* ====================================================================== */
