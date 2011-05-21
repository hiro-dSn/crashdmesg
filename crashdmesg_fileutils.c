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
		fprintf(stderr, "%s Get file stat failed: [%d] %s: %s\n", estr,
		        errno, strerror(errno), file->filename);
		return RETVAL_FAILURE;
	}
	file->fdesc = open(file->filename, O_RDONLY|O_LARGEFILE);
	if (file->fdesc == -1) {
		fprintf(stderr, "%s Can not open file: [%d] %s: %s\n", estr,
		       errno, strerror(errno), file->filename);
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
		fprintf(stderr, "%s Can not close file: [%d] %s: %s\n", estr,
		       errno, strerror(errno), file->filename);
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
		fprintf(stderr, "%s Seek failed: %s(0x%x) : [%d] %s\n", estr,
		        file->filename, (unsigned) offset, errno, strerror(errno));
		return RETVAL_FAILURE;
	}
	
	/* Read */
	readbytes = read(file->fdesc, buffer, size);
	if (readbytes ==  -1) {
		fprintf(stderr, "%s Read failed: %s(0x%x:0x%x) : [%d] %s\n", estr,
		        file->filename, (unsigned) offset, (unsigned) size,
		        errno, strerror(errno));
		return RETVAL_FAILURE;
	}
	else if (readbytes != (ssize_t) size) {
		fprintf(stderr, "%s Can not read: %s(0x%x:0x%x,0x%x) : [%d] %s\n",
		        estr, file->filename, (unsigned) offset, (unsigned) size,
		        (unsigned) readbytes, errno, strerror(errno));
		return RETVAL_FAILURE;
	}
	
	return RETVAL_SUCCESS;
}


/* ====================================================================== */
