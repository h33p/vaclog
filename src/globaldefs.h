#ifndef GLOBALDEFS_H
#define GLOBALDEFS_H

#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/stacktrace.h>

typedef asmlinkage long (*syscallFn)(const struct pt_regs*);
typedef struct filename* (*getnameFn)(const char __user*, int, int*);
typedef void (*save_stack_trace_userFn)(struct stack_trace*);
typedef unsigned long (*fdget_posFn)(unsigned int);
typedef unsigned long (*f_unlock_posFn)(struct file*);

extern syscallFn sct64_backup[];
extern syscallFn sct32_backup[];

extern save_stack_trace_userFn _save_stack_trace_user;
extern getnameFn _getname_flags;
extern fdget_posFn _fdget_pos;
extern f_unlock_posFn _f_unlock_pos;

extern pid_t targetPID;
extern pid_t steamPID;
extern char procName[];

void print_user_stack(void);

#endif
