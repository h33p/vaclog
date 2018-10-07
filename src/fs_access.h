#ifndef FS_ACCESS_H
#define FS_ACCESS_H

#include <asm/segment.h>
#include <linux/uaccess.h>
#include <linux/buffer_head.h>

struct file* kernel_open(const char* path, int flags, int rights, int* err);
void kernel_close(struct file* file);
int file_sync(struct file* file);

#endif
