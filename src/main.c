#include "vaclog.h"
#include "hooks.h"
#include "scantrack.h"

syscallFn* sct64 = NULL;
syscallFn sct64_backup[322];
syscallFn* sct32 = NULL;
syscallFn sct32_backup[544];

pid_t steamPID = 0;
char procName[256];

stack_trace_save_userFn _stack_trace_save_user = NULL;
getnameFn _getname_flags = NULL;
fdget_posFn _fdget_pos = NULL;
f_unlock_posFn _f_unlock_pos = NULL;

vacctx_t ctx;

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
	_stack_trace_save_user = (stack_trace_save_userFn)kallsyms_lookup_name("stack_trace_save_user");
	_fdget_pos = (fdget_posFn)kallsyms_lookup_name("__fdget_pos");
	_f_unlock_pos = (f_unlock_posFn)kallsyms_lookup_name("__f_unlock_pos");

    initialize_vac_context(&ctx);

	ewrite();

	prepare_sct();

	hook_syscall(sct32, __NR_ia32_open, &_open32);
	hook_syscall(sct32, __NR_ia32_openat, &_openat32);
	hook_syscall(sct32, __NR_ia32_mmap2, &_mmap32);
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

	free_vac_context(&ctx);
}

static int vaclog_proc_show(struct seq_file* m, void* v)
{
	seq_print_vac_context(&ctx, m);
	return 0;
}

static int vaclog_proc_open(struct inode* i, struct file* f)
{
	return single_open(f, vaclog_proc_show, 0);
}

static ssize_t vaclog_write(struct file* file, const char __user* buffer, size_t count, loff_t* pos)
{
	char buf[1024], pidString[256];
	size_t rcount = count;

	if (rcount > 1024)
		rcount = 1024;

	if (copy_from_user(buf, buffer, rcount))
		return -EFAULT;

	buf[1023] = '\0';

	sscanf(buf, "%d %d", &ctx.pid, &steamPID);
	sprintf(pidString, "%d/", ctx.pid);

	strcpy(procName, "/");
	strcat(procName, pidString);

	printk("Log PID: %d\n", ctx.pid);
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
	unsigned long entries[20];
	unsigned int nr_entries;
	pid_t pid = task_pid_nr(current);
	if (!_stack_trace_save_user)
		return;
	printk("Stack Trace of PID %d (%s)\n", pid, current->comm);
	nr_entries = _stack_trace_save_user(entries, ARRAY_SIZE(entries));
	stack_trace_print(entries, nr_entries, 0);
}

unsigned long get_user_stack(int idx)
{
	unsigned long entries[20];
	entries[idx] = 0;
	if (!_stack_trace_save_user)
		return 0;
	_stack_trace_save_user(entries, ARRAY_SIZE(entries));
	return entries[idx];
}

struct vm_area_struct* find_vm_area_entry(struct vm_area_struct* map, uint64_t addr)
{
	while (map) {
		if (map->vm_start <= addr && map->vm_end > addr)
			return map;

		map = map->vm_next;
	}

	return NULL;
}

int address_module_offset(pid_t pid, uint64_t addr, char* buf, size_t buflen, off_t* offset, size_t* sz, char* permissions)
{
	struct task_struct* task = pid_task(find_vpid(pid), PIDTYPE_PID);
	struct mm_struct* mm = NULL;
	struct vm_area_struct* map = NULL;
	struct file* file = NULL;
	char namebuf[512];
	const char* name = namebuf;

	if (!task)
		return -1;

	mm = task->mm;
	spin_lock(&mm->page_table_lock);
	map = mm->mmap;

	if (!map) {
		spin_unlock(&mm->page_table_lock);
		return -2;
	}

	map = find_vm_area_entry(map, addr);

	if (map) {
		namebuf[511] = '\0';

		file = map->vm_file;

		if (file)
			name = dentry_path_raw(file->f_path.dentry, namebuf, 512);
		else if (map->vm_ops && map->vm_ops->name)
			name = map->vm_ops->name(map);
		else {
			if (!map->vm_mm)
				name = "[vdso]";
			else if (map->vm_start <= map->vm_mm->brk && map->vm_end >= map->vm_mm->start_brk)
				name = "[heap]";
			else if (map->vm_start <= map->vm_mm->start_stack && map->vm_end >= map->vm_mm->start_stack)
				name = "[stack]";
			else
				name = "[anon]";
		}

		if (offset)
			*offset = addr - map->vm_start;
		if (sz)
			*sz = map->vm_end - map->vm_start;
		if (permissions)
			*permissions = map->vm_flags;

		strncpy(buf, name, buflen);
		spin_unlock(&mm->page_table_lock);

		return 0;
	}

	spin_unlock(&mm->page_table_lock);
	return -3;
}

module_init(vaclog_init);
module_exit(vaclog_exit);
