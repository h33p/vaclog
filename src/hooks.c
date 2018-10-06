#include "hooks.h"
#include "hook_handlers.h"

/*static inline void _fdput_pos(struct fd f)
{
	if (f.flags & FDPUT_POS_UNLOCK)
		_f_unlock_pos(f.file);
	fdput(f);
}*/

asmlinkage long _process_vm_readv(const struct pt_regs* regs)
{
	handle_process_readv_hook(regs->di, (const struct iovec __user*)regs->si, regs->dx, (const struct iovec __user*)regs->r10, regs->r8, regs->r9);
    return sct64_backup[__NR_process_vm_readv](regs);
}

asmlinkage long _process_vm_readv32(const struct pt_regs* regs)
{
	handle_process_readv_hook(regs->bx, (const struct iovec __user*)regs->cx, regs->dx, (const struct iovec __user*)regs->si, regs->di, regs->bp);
    return sct32_backup[__NR_ia32_process_vm_readv](regs);
}

asmlinkage long _open32(const struct pt_regs* regs)
{
	handle_open_hook((const char*)regs->bx, -1, regs->cx, regs->dx);
	return sct32_backup[__NR_ia32_open](regs);
}

asmlinkage long _openat32(const struct pt_regs* regs)
{
	handle_open_hook((const char*)regs->cx, regs->bx, regs->dx, regs->si);
	return sct32_backup[__NR_ia32_openat](regs);
}

asmlinkage long _open(const struct pt_regs* regs)
{
	handle_open_hook((const char*)regs->di, -1, regs->si, regs->dx);
	return sct64_backup[__NR_open](regs);
}

asmlinkage long _openat(const struct pt_regs* regs)
{
	handle_open_hook((const char*)regs->si, regs->di, regs->dx, regs->r10);
	return sct64_backup[__NR_openat](regs);
}

asmlinkage long _mmap(const struct pt_regs* regs)
{
	handle_mmap_hook(regs->di, regs->si, regs->dx, regs->r10, regs->r8, regs->r9);
	return sct64_backup[__NR_mmap](regs);
}

asmlinkage long _mmap32(const struct pt_regs* regs)
{
	handle_mmap_hook(regs->bx, regs->cx, regs->dx, regs->si, regs->di, regs->bp);
	return sct32_backup[__NR_ia32_mmap](regs);
}

asmlinkage long _munmap(const struct pt_regs* regs)
{
	handle_munmap_hook(regs->di, regs->si);
	return sct64_backup[__NR_munmap](regs);
}

asmlinkage long _munmap32(const struct pt_regs* regs)
{
	handle_munmap_hook(regs->bx, regs->cx);
	return sct32_backup[__NR_ia32_munmap](regs);
}

asmlinkage long _pread(const struct pt_regs* regs)
{
	if (!handle_pread64_hook(regs->di, (void*)regs->si, regs->dx, regs->r10, 0))
		return -EPERM;

	return sct64_backup[__NR_pread64](regs);
}

asmlinkage long _pread32(const struct pt_regs* regs)
{
	long ret = sct32_backup[__NR_ia32_pread64](regs);

	/* Offset is passed in 2 registers on x32 */
	if (!handle_pread64_hook(regs->bx, (void*)regs->cx, regs->dx, regs->si | (regs->di << 32ull), ret))
		return -EPERM;

	return ret;
}

asmlinkage long _read(const struct pt_regs* regs)
{
	long fpos = 0;

	if (_fdget_pos && _f_unlock_pos) {
		/*struct fd f = __to_fd(_fdget_pos(regs->di));
		long fpos = 0;
		if (f.file)
			fpos = f.file->f_pos;
			_fdput_pos(f);*/

		if (!handle_pread64_hook(regs->bx, (void*)regs->cx, regs->dx, fpos, 0))
			return -EPERM;
	}

	return sct64_backup[__NR_read](regs);
}

asmlinkage long _read32(const struct pt_regs* regs)
{
	long ret = sct32_backup[__NR_ia32_read](regs);
	long fpos = 0;

	if (_fdget_pos && _f_unlock_pos) {
		/*struct fd f = __to_fd(_fdget_pos(regs->bx));
		long fpos = 0;
		if (f.file)
			fpos = f.file->f_pos;
			_fdput_pos(f);*/

		if (!handle_pread64_hook(regs->bx, (void*)regs->cx, regs->dx, fpos, ret))
			return -EPERM;
	}

	return ret;
}
