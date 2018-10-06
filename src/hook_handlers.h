#ifndef HOOK_HANDLERS_H
#define HOOK_HANDLERS_H

#include "globaldefs.h"

void handle_process_readv_hook(pid_t pid, const struct iovec __user* lvec, uint64_t lveccnt, const struct iovec __user* rvec, uint64_t rveccnt, uint64_t flags);
void handle_open_hook(const char __user* pathname, uint64_t dfd, uint64_t flags, umode_t mode);
void handle_mmap_hook(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off);
void handle_munmap_hook(unsigned long addr, unsigned long len);
int handle_pread64_hook(int fd, void* buf, size_t count, off_t offset, long ret);

#endif
