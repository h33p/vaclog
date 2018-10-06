#include "vaclog.h"
#include "hooks.h"

syscallFn* sct64 = NULL;
syscallFn sct64_backup[322];
syscallFn* sct32 = NULL;
syscallFn sct32_backup[544];

pid_t targetPID = -1;
pid_t steamPID = 0;
char procName[256];

save_stack_trace_userFn _save_stack_trace_user = NULL;
getnameFn _getname_flags = NULL;
fdget_posFn _fdget_pos = NULL;
f_unlock_posFn _f_unlock_pos = NULL;

static const struct file_operations vaclog_proc_fops = {
	.owner = THIS_MODULE,
	.open = vaclog_proc_open,
	.read = seq_read,
	.write = vaclog_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init vaclog_init(void) {
	strcpy(procName, "/proc/-1/");

    sct64 = (syscallFn*)kallsyms_lookup_name("sys_call_table");
    sct32 = (syscallFn*)kallsyms_lookup_name("ia32_sys_call_table");
	_getname_flags = (getnameFn)kallsyms_lookup_name("getname_flags");
	_save_stack_trace_user = (save_stack_trace_userFn)kallsyms_lookup_name("save_stack_trace_user");
	_fdget_pos = (fdget_posFn)kallsyms_lookup_name("__fdget_pos");
	_f_unlock_pos = (f_unlock_posFn)kallsyms_lookup_name("__f_unlock_pos");

	ewrite();

	prepare_sct();

	/*hook_syscall(sct64, __NR_process_vm_readv, &_process_vm_readv);*/
	/*hook_syscall(sct64, __NR_open, &_open);
	  hook_syscall(sct64, __NR_openat, &_openat);*/
	hook_syscall(sct64, __NR_mmap, &_mmap);
	/*hook_syscall(sct64, __NR_munmap, &_munmap);*/
	/*hook_syscall(sct64, __NR_pread64, &_pread);
	hook_syscall(sct64, __NR_read, &_read);*/

	/*hook_syscall(sct32, __NR_ia32_process_vm_readv, &_process_vm_readv32);*/
	hook_syscall(sct32, __NR_ia32_open, &_open32);
	hook_syscall(sct32, __NR_ia32_openat, &_openat32);
	/*hook_syscall(sct32, __NR_ia32_mmap, &_mmap32);*/
	/*hook_syscall(sct32, __NR_ia32_munmap, &_munmap32);*/
	hook_syscall(sct32, __NR_ia32_pread64, &_pread32);
	hook_syscall(sct32, __NR_ia32_read, &_read32);

	dwrite();

	proc_create("vaclog", 0, 0, &vaclog_proc_fops);
	return 0;
}

static void __exit vaclog_exit(void) {
	remove_proc_entry("vaclog", NULL);

	ewrite();

	restore_sct();

	dwrite();
}

static int vaclog_proc_show(struct seq_file* m, void* v)
{
	return 0;
}

static int vaclog_proc_open(struct inode* i, struct file* f)
{
	return single_open(f, vaclog_proc_show, 0);
}

static ssize_t vaclog_write(struct file* file, const char __user* buffer, unsigned long count, loff_t* pos)
{
	char buf[1024], pidString[256];
	size_t rcount = count;

	if (rcount > 1024)
		rcount = 1024;

	if (copy_from_user(buf, buffer, rcount))
		return -EFAULT;

	buf[1023] = '\0';

	sscanf(buf, "%d %d", &targetPID, &steamPID);
	sprintf(pidString, "%d/", targetPID);

	strcpy(procName, "/");
	strcat(procName, pidString);

	printk("Log PID: %d\n", targetPID);
	printk("Steam PID: %d\n", steamPID);
	printk("Proc name: %s\n", procName);

	return rcount;
}

static void ewrite(void)
{
	write_cr0(read_cr0() & (~0x10000));
}

static void dwrite(void)
{
	write_cr0(read_cr0() | 0x10000);
}

static void prepare_sct(void)
{
	if (sct64)
		memcpy(sct64_backup, sct64, sizeof(sct64_backup));

	if (sct32)
		memcpy(sct32_backup, sct32, sizeof(sct32_backup));
}

static void restore_sct(void)
{
	if (sct64)
		memcpy(sct64, sct64_backup, sizeof(sct64_backup));

	if (sct32)
		memcpy(sct32, sct32_backup, sizeof(sct32_backup));
}

static void hook_syscall(syscallFn* sct, int syscall, syscallFn function)
{
	printk("Hook %d\n", syscall);
	((volatile syscallFn*)sct)[syscall] = function;
}

void print_user_stack(void)
{
	struct stack_trace trace;
	unsigned long entries[20];
	pid_t pid = task_pid_nr(current);
	if (!_save_stack_trace_user)
		return;
	trace.nr_entries = 0;
	trace.max_entries = 5;
	trace.skip = 0;
	trace.entries = entries;
	printk("Stack Trace of PID %d (%s)\n", pid, current->comm);
	_save_stack_trace_user(&trace);
	print_stack_trace(&trace, 5);
}

module_init(vaclog_init);
module_exit(vaclog_exit);
