#include "hook_handlers.h"
#include "scantrack.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26)
#include <linux/fdtable.h>
#endif
#include <linux/file.h>
#include <linux/mount.h>

void handle_process_readv_hook(pid_t pid, const struct iovec __user* lvec, uint64_t lveccnt, const struct iovec __user* rvec, uint64_t rveccnt, uint64_t flags)
{
	pid_t cpid = task_pid_nr(current);
	if (steamPID != 0 && cpid != steamPID)
		return;

	if (lveccnt > 10000 || rveccnt > 10000)
		return;

	if (lveccnt > rveccnt)
		lveccnt = rveccnt;
	if (rveccnt > lveccnt)
		rveccnt = lveccnt;

	if (pid == ctx.pid) {
		struct iovec localvec[lveccnt];
		struct iovec remotevec[rveccnt];
		int i;

		if (copy_from_user(localvec, lvec, sizeof(struct iovec) * lveccnt))
			return;
		if (copy_from_user(remotevec, rvec, sizeof(struct iovec) * rveccnt))
			return;

		printk("vaclog: Read from target PID (%d)!\nThese memory ranges are read:\n", pid);
		print_user_stack();

		for (i = 0; i < lveccnt; i++)
			printk("vaclog: %llx\t<--\t%llx [%lx]\n", (uint64_t)localvec[i].iov_base, (uint64_t)remotevec[i].iov_base, localvec[i].iov_len);
	}
}

void handle_open_hook(const char __user* pathname, uint64_t dfd, uint64_t flags, umode_t mode)
{
	pid_t pid = task_pid_nr(current);
    char name[1024];

	if (steamPID != 0 && pid != steamPID)
		return;

	strncpy_from_user(name, pathname, 1024);
	name[1023] = '\0';

	if (strstr(name, procName)) {
		printk("vaclog: Open file on target PID! [%s] (%lld %llx %hx)\n", name, dfd, flags, mode);
		print_user_stack();
	}
}

void handle_mmap_hook(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off)
{
	pid_t cpid = task_pid_nr(current);
	char name[1024];
	struct file* file = NULL;

	if (0 && cpid == ctx.pid) {
		printk("vaclog: MMAP on target PID! [%lu @ %lx] (%lu %lu)\n", len, addr, fd, off);
		print_user_stack();
		return;
	}

	if (steamPID != 0 && cpid != steamPID)
		return;

    file = fget(fd);
	if (!file)
		return;
	dentry_path_raw(file->f_path.dentry, name, 1024);
	fput(file);
	name[1023] = '\0';
	if (strstr(name, procName)) {
		printk("vaclog: MMAP: %s\n", name);
		print_user_stack();
	}
}

void handle_munmap_hook(unsigned long addr, unsigned long len)
{
	pid_t cpid = task_pid_nr(current);

	if (cpid == ctx.pid) {
		printk("vaclog: MUNMAP on target PID! [%lu @ %lx]\n", len, addr);
		print_user_stack();
		return;
	}
}

int handle_pread64_hook(int fd, void* buf, size_t count, off_t offset, long ret)
{
	pid_t cpid = task_pid_nr(current);
	long count2 = ret;
	struct file* file = NULL;
	char path[512];
	char* name;
	char readbuf[0x20 * 3];
	char lbuf[0x20];
	char mapname[128];
	off_t fileoffset = 0;
	int addrret = 0;
	int i;

	if (steamPID != 0 && cpid != steamPID)
		return 1;

	if (ret > 0x20)
		count2 = 0x20;
	if (ret < 0)
		count2 = 0;

    file = fget(fd);
	if (!file)
		return 1;
	name = dentry_path_raw(file->f_path.dentry, path, 512);
	path[511] = '\0';
	fput(file);

	if (strstr(name, procName)) {

		if (strstr(name, "mem"))
			handle_vac_scan(&ctx, offset, count);

		addrret = address_module_offset(ctx.pid, offset, mapname, 128, &fileoffset, NULL, NULL);
		if (addrret)
			mapname[0] = '\0';

		if (0) {
			printk("vaclog: PREAD64: %s [%lu @ %#lx, %s @ %#lx] (%ld) -> %p\n", name, count, offset, mapname, fileoffset, ret, buf);
			memset(readbuf, ' ', sizeof(readbuf));
			if (!strstr(name, "map")) {
				copy_from_user(lbuf, buf, count2);
				for (i = 0; i < count2; i++)
					sprintf(readbuf + i * 3, "%02hhx ", lbuf[i]);
				if (count2) {
					readbuf[count2 * 3 - 1] = '\0';
					lbuf[count2 - 1] = '\0';
				} else {
					readbuf[0] = 0;
					lbuf[0] = 0;
				}
				printk("Showing the first bytes read: %s\n", readbuf);
			}
			print_user_stack();
		}
		/*return 0;*/
	}
	return 1;
}
