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
static int crashdmesg(VMCore *vmcore);


/* ============================================================
       main() - MAIN
   ============================================================ */
int main(int argc, char *argv[])
{
	/* --- Variables --- */
	char estr[] = "[ERROR] main:";
	VMCore vmcore;
	memset(&vmcore, 0x00, sizeof(VMCore));
	
	fprintf(stdout, "%s:  %s start.\n", APP_NAME, APP_NAME);
	
	/* Check args */
	if (parse_option(argc, argv, &vmcore.file)) {
		fprintf(stderr, "%s Invalid option.\n", estr);
		print_usage();
		return RETVAL_FAILURE;
	}
	fprintf(stdout, "%s:   Target file: %s\n", APP_NAME, vmcore.file.filename);
	
	/* Do crashdmesg */
	if (crashdmesg(&vmcore)) {
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
static int crashdmesg(VMCore *vmcore)
{
	/* --- Variables --- */
	char estr[] = "[ERROR] crashdmesg:";
	int loop = 0;
	Elf64_Phdr phdr_cache;
	memset(&phdr_cache, 0x00, sizeof(Elf64_Phdr));
	char osrelease[OSRELEASE_LENGTH];
	memset(osrelease, 0x00, sizeof(osrelease));
	time_t crashtime = 0;
	struct tm *ct = NULL;

	/* ringbuffer info from vmcoreinfo */
	uint64_t log_buf_vaddr = 0;
	uint64_t log_end_vaddr = 0;
	uint64_t log_buf_len_vaddr = 0;
	uint64_t logged_chars_vaddr = 0;
	
	/* ringbuffer address and size */
	uint64_t log_buf = 0;
	uint32_t log_end = 0;
	int32_t log_buf_len = 0;
	uint32_t logged_chars = 0;
	
	/* Pointer of ring buffer */
	off_t ringbuffer1 = 0; /* file offset */
	uint32_t ringbuffer1_size = 0;
	off_t ringbuffer2 = 0; /* file offset */
	uint32_t ringbuffer2_size = 0;
	char *ringbuffer = NULL;
	
	/* --- Assert check --- */
	assert(vmcore != NULL);
	
	/* Open vmcore file and validate */
	fprintf(stdout, "%s:  Validate vmcore ELF binary header.\n", APP_NAME);
	if (file_open(&vmcore->file)) {
		fprintf(stderr, "%s Can not open vmcore file.\n", estr);
		return RETVAL_FAILURE;
	}
	if (elf_validate_elfheader(vmcore)) {
		fprintf(stderr, "%s Failed to validate vmcore file.\n", estr);
		goto ERROR_CLOSE;
	}
	
	/* Search and Read VMCOREINFO */
	fprintf(stdout, "%s:  Read VMCOREINFO from NOTE segment.\n", APP_NAME);
	if (elf_read_vmcoreinfo(vmcore)) {
		fprintf(stderr, "%s Can not read VMCOREINFO.\n", estr);
		goto ERROR_CLOSE;
	}

	/* Read additional informations */
	if (elf_read_osrelease(vmcore, osrelease, sizeof(osrelease))) {
		fprintf(stderr, "%s Can not read OSRELEASE.\n", estr);
		goto ERROR_CLOSE;
	}
	fprintf(stdout, "%s:    * OS Release: %s\n", APP_NAME, osrelease);
	if (elf_read_crashtime(vmcore, &crashtime)) {
		fprintf(stderr, "%s Can not read CRASHTIME.\n", estr);
		goto ERROR_CLOSE;
	}
	fprintf(stdout, "%s:    * Crash Time: %ld,\n", APP_NAME, crashtime);
	ct = localtime(&crashtime);
	if (ct == NULL) {
		fprintf(stderr, "%s localtime failed.\n", estr);
		return RETVAL_FAILURE;
	}
	fprintf(stdout, "%s:                  %04d/%02d/%02d %02d:%02d:%02d\n",
	        APP_NAME, ct->tm_year+1900, ct->tm_mon+1, ct->tm_mday,
	        ct->tm_hour, ct->tm_min, ct->tm_sec);
	
	/* Read vaddr of ringbuffer */
	fprintf(stdout, "%s:  Read Symbol from VMCOREINFO.\n", APP_NAME);
	elf_search_vmcoreinfo_symbol(vmcore, "log_buf", &log_buf_vaddr);
	elf_search_vmcoreinfo_symbol(vmcore, "log_end", &log_end_vaddr);
	elf_search_vmcoreinfo_symbol(vmcore, "log_buf_len", &log_buf_len_vaddr);
	elf_search_vmcoreinfo_symbol(vmcore, "logged_chars", &logged_chars_vaddr);
	if ((! log_buf_vaddr) || (! log_end_vaddr) ||
	    (! log_buf_len_vaddr) || (! logged_chars_vaddr)) {
		fprintf(stderr, "%s Can not read Symbol from VMCOREINFO.\n", estr);
		goto ERROR_CLOSE;
	}
	fprintf(stdout, "%s:    * log_buf:      0x%016lx\n",
	        APP_NAME, log_buf_vaddr);
	fprintf(stdout, "%s:    * log_end:      0x%016lx\n",
	        APP_NAME, log_end_vaddr);
	fprintf(stdout, "%s:    * log_buf_len:  0x%016lx\n",
	        APP_NAME, log_buf_len_vaddr);
	fprintf(stdout, "%s:    * logged_chars: 0x%016lx\n",
	        APP_NAME, logged_chars_vaddr);

	/* Read LOAD segment */
	fprintf(stdout, "%s:  Read LOAD section about Ring buffer..\n",
	        APP_NAME);
	elf_read_load_uint64(vmcore, &phdr_cache,
	                     log_buf_vaddr, &log_buf);
	elf_read_load_uint32(vmcore, &phdr_cache,
	                     log_end_vaddr, &log_end);
	elf_read_load_int32(vmcore, &phdr_cache,
	                    log_buf_len_vaddr, &log_buf_len);
	elf_read_load_uint32(vmcore, &phdr_cache,
	                     logged_chars_vaddr, &logged_chars);
	if ((! log_buf) || (! log_end) ||
	    (! log_buf_len) || (! logged_chars)) {
		fprintf(stderr, "%s Can not read value from LOAD segment.\n", estr);
		goto ERROR_CLOSE;
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
		goto ERROR_CLOSE;
	}

	/* Allocate memory for ring buffer */
	ringbuffer = malloc(log_buf_len);
	if (ringbuffer == NULL) {
		fprintf(stderr, "%s Can not allocate memory.\n", estr);
		goto ERROR_CLOSE;
	}
	
	/* Calculate Dump address */
	fprintf(stdout, "%s:  Calculating dump area address.\n", APP_NAME);
	if ( logged_chars < log_buf_len ) {
		/* ring buffer not filled */
		ringbuffer1_size = logged_chars;
		if (elf_search_load_data(vmcore, &phdr_cache,
		                          log_buf, ringbuffer1_size, &ringbuffer1)) {
			fprintf(stderr, "%s Ring buffer not found in vmcore.\n", estr);
			goto ERROR_FREE;
		}   
		fprintf(stdout, "%s:   Ring buffer Part: 1/1\n", APP_NAME);
		fprintf(stdout, "%s:    * File Offset:  0x%016lx\n",
		        APP_NAME, ringbuffer1);
		fprintf(stdout, "%s:    * Size:                 0x%08x\n",
		        APP_NAME, ringbuffer1_size);
		/* DUMP */
		if (file_read(&vmcore->file, (void*) ringbuffer,
			          ringbuffer1, ringbuffer1_size)) {
			fprintf(stderr, "%s Can not read ring buffer.\n", estr);
			goto ERROR_FREE;
		}
		fprintf(stdout, "%s:  Dump ring buffer.\n", APP_NAME);
		fprintf(stdout,
		        ">>>>>>>>>>[ START kernel ring buffer ]>>>>>>>>>>>>>>>>>\n");
		for (loop = 0; loop < log_buf_len; loop++) {
		     fputc(ringbuffer[loop], stdout);
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
			goto ERROR_FREE;
		}
		if (elf_search_load_data(vmcore, &phdr_cache,
		                         log_buf + (log_end & (log_buf_len-1)),
		                         ringbuffer1_size, &ringbuffer1) ||
		    elf_search_load_data(vmcore, &phdr_cache, log_buf,
		                         ringbuffer2_size, &ringbuffer2)) {
			fprintf(stderr, "%s Ring buffer not found in vmcore.\n", estr);
			goto ERROR_FREE;
		}
		fprintf(stdout, "%s:   Ring buffer Part: 1/2\n", APP_NAME);
		fprintf(stdout, "%s:    * File Offset:  0x%016lx\n",
		        APP_NAME, ringbuffer1);
		fprintf(stdout, "%s:    * Size:                 0x%08x\n",
		        APP_NAME, ringbuffer1_size);
		fprintf(stdout, "%s:   Ring buffer Part: 2/2\n", APP_NAME);
		fprintf(stdout, "%s:    * File Offset:  0x%016lx\n",
		        APP_NAME, ringbuffer2);
		fprintf(stdout, "%s:    * Size:                 0x%08x\n",
		        APP_NAME, ringbuffer2_size);
		/* DUMP */
		if (file_read(&vmcore->file, (void*) ringbuffer,
			          ringbuffer1, ringbuffer1_size) ||
		    file_read(&vmcore->file, (void*) ringbuffer + ringbuffer1_size,
		              ringbuffer2, ringbuffer2_size)) {
			fprintf(stderr, "%s Can not read ring buffer.\n", estr);
			goto ERROR_FREE;
		}
		fprintf(stdout, "%s:  Dump ring buffer.\n", APP_NAME);
		fprintf(stdout,
		        ">>>>>>>>>>[ START kernel ring buffer ]>>>>>>>>>>>>>>>>>\n");
		for (loop = 0; loop < log_buf_len; loop++) {
			fputc(ringbuffer[loop], stdout);
		}
		fprintf(stdout,
		        "<<<<<<<<<<[ END kernel ring buffer   ]<<<<<<<<<<<<<<<<<\n");
	}
	
	fprintf(stdout, "%s: Dump complete.\n", APP_NAME);
	
	/* free ringbuffer andclose file */
	free(ringbuffer);
	file_close(&vmcore->file);
	
	return RETVAL_SUCCESS;
	
	/* Error */
ERROR_FREE:
	free(ringbuffer);
ERROR_CLOSE:
	file_close(&vmcore->file);

	return RETVAL_FAILURE;
}


/* ====================================================================== */
