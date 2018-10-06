#ifndef VACLOG_H
#define VACLOG_H

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Heep");
MODULE_DESCRIPTION("A logger of VAC activity.");

#include "globaldefs.h"

static void ewrite(void);
static void dwrite(void);

static void prepare_sct(void);
static void restore_sct(void);
static void hook_syscall(syscallFn* sct, int syscall, syscallFn function);

static int vaclog_proc_show(struct seq_file* m, void* v);
static int vaclog_proc_open(struct inode* i, struct file* f);
static ssize_t vaclog_write(struct file* file, const char __user* buffer, unsigned long count, loff_t* pos);

#endif
