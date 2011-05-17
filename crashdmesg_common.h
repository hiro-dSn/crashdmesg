/* ======================================================================
       crashdmesg - VMCore Kernel Ring Buffer Dumper
       [ crashdmesg_common.h ]
       Copyright(c) 2011 by Hiroshi KIHIRA.
   ====================================================================== */

#ifndef CRASHDMESG_COMMON_H
#define CRASHDMESG_COMMON_H

#ifndef _LARGEFILE64_SOURCE
#  define _LARGEFILE64_SOURCE
#endif


/* --- Include system header files --- */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <elf.h>


/* --- Constant values --- */
#define RETVAL_SUCCESS 0
#define RETVAL_FAILURE 1

#define APP_NAME "crashdmesg"
#define APP_FULLNAME "VMCore Kernel Ring Buffer Dumper"
#define APP_VERSION "0.1"

#define DEFAULT_VMCORE "/proc/vmcore"
#define MAX_LOGBUF_LIMIT 1048576 /* 1MB */


/* --- Data structures --- */

/* File descriptor and Filesize */
typedef struct {
	char   *filename;
	int    fdesc;
	size_t size;
} File;


/* --- Common Prototypes --- */
int file_open(File *file);
int file_close(File *file);
int file_read(File *file, void *buffer, off_t offset, size_t size);
int file_mmap(File *file, void* *buffer, off_t offset, size_t size);
int file_munmap(void* *buffer, size_t size);
int elf_validate_header(File *file, Elf64_Ehdr *header);
int elf_mmap_vmcore(File *file, uint8_t* *buffer);
int elf_munmap_vmcore(File *file, uint8_t* *buffer);
int elf_search_note_section(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                            uint8_t* *note, size_t *size);
int elf_search_vmcoreinfo(uint8_t *note, size_t size, char *key, uint64_t *res);
int elf_read_uint64_from_load(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                              uint64_t vaddr, uint64_t *ret);
int elf_read_uint32_from_load(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                              uint64_t vaddr, uint32_t *ret);
int elf_read_int32_from_load(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                              uint64_t vaddr, int32_t *ret);
int elf_read_load_section(File *file, uint8_t *buffer, Elf64_Ehdr *header,
                          uint64_t vaddr, size_t size, uint8_t* *ret);


#endif /* ! CRASHDMESG_COMMON_H */

/* ====================================================================== */
