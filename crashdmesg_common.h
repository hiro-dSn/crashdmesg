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
#include <time.h>


/* --- Constant values --- */
#define RETVAL_SUCCESS 0
#define RETVAL_FAILURE 1

#define APP_NAME "crashdmesg"
#define APP_FULLNAME "VMCore Kernel Ring Buffer Dumper"
#define APP_VERSION "0.9.1"

#define DEFAULT_VMCORE "/proc/vmcore"
#define MAX_LOGBUF_LIMIT 1048576 /* 1MB */
#define VMCOREINFO_MAX_SIZE 4096 /* Max size of vmcoreinfo.
                                    See:include/linux/kexec.h */
#define MAX_SYMBOL_NAME 64 /* Symbol name size */
#define OSRELEASE_LENGTH 65 /* Size of "new_utsname.release"
                               See:include/linux/utsname.h */
#define CRASHTIME_LENGTH 20 /* Text size of decimal 2^64-1 */
#define NOTETYPE_VMCOREINFO 0x00000000 /* Elf64_Nhdr.n_type */


/* --- Data structures --- */

/* File descriptor and Filesize */
typedef struct {
	char   *filename;
	int    fdesc;
	size_t size;
} File;

/* Keep file descriptor and vmcore information */
typedef struct {
	File file;
	Elf64_Ehdr elf_header;
	char vmcoreinfo[VMCOREINFO_MAX_SIZE];
	size_t vmcoreinfo_size; /* vmcoreinfo real size */
	char *osrelease[OSRELEASE_LENGTH];
	size_t osrelease_size; /* osrelease real size */
	time_t crashtime; /* CRASHTIME value [sec] */
	uint64_t log_buf; /* log_buf [virtual address] */
	uint64_t log_end; /* log_end [virtual address] */
	int32_t log_buf_len; /* log_buf_len [size] */
	uint32_t logged_chars; /* logged_chars [size] */
} VMCore;


/* --- Common Prototypes --- */
int file_open(File *file);
int file_close(File *file);
int file_read(File *file, void *buffer, off_t offset, size_t size);
int elf_validate_elfheader(VMCore *vmcore);
int elf_read_vmcoreinfo(VMCore *vmcore);
int elf_search_vmcoreinfo_symbol(VMCore *vmcore, char *key, uint64_t *ret);
int elf_search_vmcoreinfo_key(VMCore *vmcore, char *key, char* *ptr);
int elf_read_load_uint64(VMCore *vmcore, Elf64_Phdr *phdr_cache,
                         uint64_t vaddr, uint64_t *ret);
int elf_read_load_uint32(VMCore *vmcore, Elf64_Phdr *phdr_cache,
                         uint64_t vaddr, uint32_t *ret);
int elf_read_load_int32(VMCore *vmcore, Elf64_Phdr *phdr_cache,
                        uint64_t vaddr, int32_t *ret);
int elf_search_load_data(VMCore *vmcore, Elf64_Phdr *phdr_cache,
                         uint64_t vaddr, size_t size, off_t *ret);
int elf_read_osrelease(VMCore *vmcore, char *buffer, size_t buffer_size);
int elf_read_crashtime(VMCore *vmcore, time_t *crashtime);


#endif /* ! CRASHDMESG_COMMON_H */

/* ====================================================================== */
