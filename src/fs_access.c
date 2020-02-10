#include "fs_access.h"

#define MAKE_MM_SEG(s)	((mm_segment_t) { (s) })

#define KERNEL_DS	MAKE_MM_SEG(-1UL)

#define get_ds()	(KERNEL_DS)

struct file* kernel_open(const char* path, int flags, int rights, int* err)
{
	struct file* filp = NULL;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if (IS_ERR(filp)) {
		if (err)
			*err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}

void kernel_close(struct file* file)
{
	filp_close(file, NULL);
}

int file_sync(struct file* file)
{
	vfs_fsync(file, 0);
	return 0;
}
