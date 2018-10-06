#ifndef HOOKS_H
#define HOOKS_H

#include "globaldefs.h"

asmlinkage long _process_vm_readv(const struct pt_regs* regs);
asmlinkage long _process_vm_readv32(const struct pt_regs* regs);

asmlinkage long _open(const struct pt_regs* regs);
asmlinkage long _openat(const struct pt_regs* regs);
asmlinkage long _open32(const struct pt_regs* regs);
asmlinkage long _openat32(const struct pt_regs* regs);

asmlinkage long _mmap(const struct pt_regs* regs);
asmlinkage long _mmap32(const struct pt_regs* regs);

asmlinkage long _munmap(const struct pt_regs* regs);
asmlinkage long _munmap32(const struct pt_regs* regs);

asmlinkage long _pread(const struct pt_regs* regs);
asmlinkage long _pread32(const struct pt_regs* regs);
asmlinkage long _read(const struct pt_regs* regs);
asmlinkage long _read32(const struct pt_regs* regs);

#endif
