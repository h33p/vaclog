#include "scantrack.h"
#include "globaldefs.h"
#include <linux/vmalloc.h>

void initialize_vac_context(vacctx_t* ctx)
{
	memset(ctx, 0, sizeof(vacctx_t));
	ctx->file_track.buf = vmalloc(sizeof(fscan_track_t) * 100);
	ctx->file_track.capacity = ctx->file_track.buf ? 100 : 0;
}

void free_vac_context(vacctx_t* ctx)
{
	vfree(ctx->file_track.buf);
}

static void fscan_track_sort(ls_fscan_track_t* ls)
{
	int i, j;
	fscan_track_t temp;

	for (i = 1; i < ls->count; i++) {
		temp = ls->buf[i];

		for (j = i - 1; j >= 0 && ls->buf[j].start > temp.start; j--)
			ls->buf[j + 1] = ls->buf[j];

		ls->buf[j + 1] = temp;
	}
}

static void fscan_track_insert(ls_fscan_track_t* ls, fscan_track_t element)
{
	if (ls->capacity <= ls->count) {
		fscan_track_t* new_buf = vmalloc(sizeof(fscan_track_t) * ls->capacity * 2);
		if (!new_buf)
			return;

		ls->capacity *= 2;
		memcpy(new_buf, ls->buf, sizeof(fscan_track_t) * ls->count);
		vfree(ls->buf);
		ls->buf = new_buf;
	}

	ls->buf[ls->count++] = element;

	fscan_track_sort(ls);
}

static fscan_track_t* fscan_insert_entry_address(ls_fscan_track_t* ls, pid_t pid, uint64_t address)
{
	off_t offset;
	size_t sz;
	fscan_track_t new_entry;
	char name[256], *c = name + 256;
	memset(new_entry.filename, 0, sizeof(new_entry.filename));

	if (address_module_offset(pid, address, name, 256, &offset, &sz, &new_entry.permissions))
		return NULL;

	while (c-- > name && *c != '/');

	strncpy(new_entry.filename, ++c, 63);
	new_entry.start = address - offset;
	new_entry.end = new_entry.start + sz;
	new_entry.scans_made = 0;
	new_entry.bytes_read = 0;

	fscan_track_insert(ls, new_entry);

	return fscan_find_entry(ls, address);
}

void handle_vac_scan(vacctx_t* ctx, uint64_t address, uint64_t len)
{
	fscan_track_t* entry = fscan_find_entry(&ctx->file_track, address);

	if (!entry)
		entry = fscan_insert_entry_address(&ctx->file_track, ctx->pid, address);

	ctx->scans_total++;

	if (!entry) {
		ctx->scans_unknown++;
		return;
	}

	entry->scans_made++;
	entry->bytes_read += len;

	if (entry->permissions & VM_EXEC)
		ctx->scans_exec++;
	else {
		printk("vaclog: non-executable region scan made! %#llx (%s, %lld @ %llx)\n", address, entry->filename, len, address - entry->start);
		ctx->scans_noexec++;
	}
}

static void seq_print_fscan_entry(const fscan_track_t* track, struct seq_file* m)
{
	seq_printf(m, "%llx-%llx", track->start, track->end);
	seq_putc(m, ' ');
	seq_putc(m, track->permissions & VM_READ ? 'r' : '-');
	seq_putc(m, track->permissions & VM_WRITE ? 'w' : '-');
	seq_putc(m, track->permissions & VM_EXEC ? 'x' : '-');
	seq_putc(m, track->permissions & VM_MAYSHARE ? 's' : 'p');
	seq_putc(m, ' ');
	seq_printf(m, "%s (%lld %lld)\n", track->filename, track->scans_made, track->bytes_read);
}

void seq_print_vac_context(vacctx_t* ctx, struct seq_file* m)
{
	int i;

	seq_printf(m, "Tracking process: %u\n", ctx->pid);
	seq_printf(m, "Number of scans made: %lld\n", ctx->scans_total);
	seq_printf(m, "Executable regions: %lld\n", ctx->scans_exec);
	seq_printf(m, "Non-executable regions: %lld\n", ctx->scans_noexec);
	if (ctx->scans_unknown)
		seq_printf(m, "Unknown regions: %lld\n", ctx->scans_unknown);

	if (ctx->file_track.count)
		seq_printf(m, "\nPer-file scans:\n");

	for (i = 0; i < ctx->file_track.count; i++)
		if (ctx->file_track.buf[i].scans_made)
			seq_print_fscan_entry(ctx->file_track.buf + i, m);
}

/* Assumes the list is sorted (as it should be) */
fscan_track_t* fscan_find_entry(ls_fscan_track_t* ls, uint64_t address)
{
	int i = 0, k = ls->count - 1;

	while (i <= k) {
		int m = i + (k - i) / 2;

		if (address >= ls->buf[m].start && address < ls->buf[m].end)
			return ls->buf + m;

		if (address < ls->buf[m].start)
			k = m - 1;
		else
			i = m + 1;
	}

	return NULL;
}
