#ifndef SCANTRACK_H
#define SCANTRACK_H

#include <linux/types.h>
#include <linux/seq_file.h>

typedef struct fscan_track_t
{
	uint64_t scans_made, bytes_read, start, end;
	char filename[64];
	char permissions;
} fscan_track_t;

typedef struct ls_fscan_track_t
{
	/* The buffer always gets sorted on element insertion */
	fscan_track_t* buf;
	size_t count, capacity;
} ls_fscan_track_t;

typedef struct vacctx_t
{
	uint64_t scans_total, scans_exec, scans_noexec, scans_unknown;
	ls_fscan_track_t file_track;
	pid_t pid;
} vacctx_t;

void initialize_vac_context(vacctx_t* ctx);
void free_vac_context(vacctx_t* ctx);
void handle_vac_scan(vacctx_t* ctx, uint64_t address, uint64_t len);
void seq_print_vac_context(vacctx_t* ctx, struct seq_file* m);

fscan_track_t* fscan_find_entry(ls_fscan_track_t* ls, uint64_t address);

#endif
