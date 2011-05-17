/* ======================================================================
       crashdmesg - VMCore Kernel Ring Buffer Dumper
       [ crashdmesg_fileutils.c ]
       Copyright(c) 2011 by Hiroshi KIHIRA.
   ====================================================================== */


/* --- Include header files --- */
#include "crashdmesg_common.h"


/* ============================================================
       file_open() - Get filesize and Open
   ============================================================ */
int file_open(File *file)
{
	/* --- Variables --- */
	errno = 0;
	char estr[] = "[ERROR] file_open:";
	struct stat filestat;
	memset(&filestat, 0x00, sizeof(struct stat));
	
	/* --- Assert check --- */
	assert(file != NULL);
	
	/* Input validation */
	if (! file->filename) {
		fprintf(stderr, "%s Filename not specified.\n", estr);
		return RETVAL_FAILURE;
	}
	if (file->fdesc) {
		fprintf(stderr, "%s File already opened.\n", estr);
		return RETVAL_FAILURE;
	}
	
	/* Get stat and Open */
	if (stat(file->filename, &filestat) == -1) {
		fprintf(stderr, "%s Get file stat failed: %s : %s\n", estr,
		        file->filename, strerror(errno));
		return RETVAL_FAILURE;
	}
	file->fdesc = open(file->filename, O_RDONLY|O_LARGEFILE);
	if (file->fdesc == -1) {
		fprintf(stderr, "%s Can not open file: %s : %s\n", estr,
		       file->filename, strerror(errno));
		file->fdesc = 0;
		return RETVAL_FAILURE;
	}
	file->size = (size_t) filestat.st_size;
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       file_close() - Close file
   ============================================================ */
int file_close(File *file)
{
	/* --- Variables --- */
	errno = 0;
	char estr[] = "[ERROR] file_close:";
	
	/* --- Assert check --- */
	assert(file != NULL);
	
	/* Check param */
	if (! file->fdesc) {
		fprintf(stderr, "%s File is not opened.\n", estr);
		return RETVAL_FAILURE;
	}
	
	/* Close */
	if (close(file->fdesc) == -1) {
		fprintf(stderr, "%s Can not close file: %s : %s\n", estr,
		       file->filename, strerror(errno));
		file->fdesc = 0;
		file->size = 0;
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       file_read() - Read data from file
   ============================================================ */
int file_read(File *file, void *buffer, off_t offset, size_t size)
{
	/* --- Variables --- */
	errno = 0;
	char estr[] = "[ERROR] file_read:";
	ssize_t readbytes = 0;
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	assert(offset >= 0);
	assert(size > 0);
	
	/* Check file and pointer */
	if (! file->fdesc) {
		fprintf(stderr, "%s File is not opened.\n", estr);
		return RETVAL_FAILURE;
	}
	if ((offset > file->size) || (offset + size > file->size)) {
		fprintf(stderr, "Read area overflowed.\n");
		return RETVAL_FAILURE;
	}
	
	/* Seek to offset */
	if (lseek(file->fdesc, offset, SEEK_SET) == (off_t) -1) {
		fprintf(stderr, "%s Seek failed: %s(0x%x) : %s\n", estr,
		        file->filename, (unsigned) offset, strerror(errno));
		return RETVAL_FAILURE;
	}
	
	/* Read */
	readbytes = read(file->fdesc, buffer, size);
	if (readbytes ==  -1) {
		fprintf(stderr, "%s Read failed: %s(0x%x:0x%x) : %s\n", estr,
		        file->filename, (unsigned) offset, (unsigned) size,
		        strerror(errno));
		return RETVAL_FAILURE;
	}
	else if (readbytes != (ssize_t) size) {
		fprintf(stderr, "%s Can not read: %s(0x%x:0x%x,0x%x) : %s\n", estr,
		        file->filename, (unsigned) offset, (unsigned) size,
		        (unsigned) readbytes, strerror(errno));
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ============================================================
       file_mmap() - Do file mmap
   ============================================================ */
int file_mmap(File *file, void* *buffer, off_t offset, size_t size)
{
	/* --- Variables --- */
	errno = 0;
	char estr[] = "[ERROR] file_mmap:";
	void *mapped_addr = NULL;
	
	/* --- Assert check --- */
	assert(file != NULL);
	assert(buffer != NULL);
	assert(offset >= 0);
	assert(size > 0);
	
	/* Check file and pointer */
	if (! file->fdesc) {
		fprintf(stderr, "%s File is not opened.\n", estr);
		return RETVAL_FAILURE;
	}
	if (*buffer != NULL) {
		fprintf(stderr, "%s Pointer already used or mmapped.\n", estr);
		return RETVAL_FAILURE;
	}
	if ((offset > file->size) || (offset + size > file->size)) {
		fprintf(stderr, "%s Mmap area overflowed: %s(0x%x,0x%x:0x%x)\n", estr,
		        file->filename, (unsigned) file->size, (unsigned) offset,
		        (unsigned) size);
		return RETVAL_FAILURE;
	}
	
	/* mmap */
	mapped_addr = mmap(NULL, size, PROT_READ, MAP_SHARED,
	                              file->fdesc, offset);
	if (mapped_addr == (void*) MAP_FAILED) {
		fprintf(stderr, "%s Mmap failed: %s(0x%x:0x%x) : %s\n", estr,
		       file->filename, (unsigned) offset, (unsigned) size,
		       strerror(errno));
		return RETVAL_FAILURE;
	}
	
	*buffer = mapped_addr;
	return RETVAL_SUCCESS;
}


/* ============================================================
       file_munmap() - Do file munmap
   ============================================================ */
int file_munmap(void* *buffer, size_t size)
{
	/* --- Variables --- */
	errno = 0;
	char estr[] = "[ERROR] file_munmap:";
	
	/* --- Assert check --- */
	assert(buffer != NULL);
	assert(size > 0);
	
	/* Check pointer */
	if (*buffer == NULL) {
		fprintf(stderr, "Invalid pointer.\n");
		return RETVAL_FAILURE;
	}
	
	/* Munmap */
	if (munmap(*buffer, size) == -1) {
		fprintf(stderr, "%s Munmap failed: %s\n", estr, strerror(errno));
		*buffer = NULL;
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}

/* ====================================================================== */