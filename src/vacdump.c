#include "vacdump.h"
#include "fs_access.h"
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/crc32.h>

int dump_vac_module(void __user* modinfo)
{
	struct {
		unsigned int buf;
		unsigned int size;
	} module_info = {0, 0};
	char* kbuf = NULL;
	uint32_t checksum = 0;
	char filename[256];
	struct file* file = NULL;
	loff_t off = 0;
	int err = 0;

	if (copy_from_user(&module_info, modinfo, sizeof(module_info)) || module_info.size < 100 || module_info.size > 0x20000)
		return -1;

	kbuf = vmalloc(module_info.size);

	if (copy_from_user(kbuf, (void*)(unsigned long)module_info.buf, module_info.size) || *(unsigned int*)kbuf ^ 0x464c457f) {
		vfree(kbuf);
		return -2;
	}

	printk("vaclog: calculating checksum\n");

	checksum = crc32(0x80000000 ^ 0xffffffff, kbuf, module_info.size) ^ 0xffffffff;
	sprintf(filename, "/tmp/%x-%x.so", checksum, module_info.size);

	printk("vaclog: openning file: %s\n", filename);

	file = kernel_open(filename, O_RDONLY, 0, &err);

	if (file || err == -13) {
		kernel_close(file);
		vfree(kbuf);
		return -3;
	}

	file = kernel_open(filename, O_CREAT|O_WRONLY, 0, &err);

	if (!file) {
		vfree(kbuf);
		return -4;
	}

	printk("vaclog: saving VAC module to: %s\n", filename);
	kernel_write(file, kbuf, module_info.size, &off);

	kernel_close(file);

	vfree(kbuf);
	return 0;
}
