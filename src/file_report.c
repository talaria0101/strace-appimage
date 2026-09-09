/*
 * file_report.c -- end-of-run report of every path the tracees touched.
 *
 * This is the strace-appimage replacement for the LD_DEBUG=libs scraping
 * that AppImage packaging scripts do today: instead of trusting the
 * dynamic loader to report what it mapped (which sees nothing for static
 * binaries and nothing for files opened outside ld.so), the tracer
 * records every path argument it decoded, per operation, with the
 * outcome, and prints a report a packager (or an agent) can act on.
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "tracing_ext.h"

#include <stdlib.h>
#include <sys/stat.h>

/*
 * Operation classes.  The syscall name is the source of truth; these
 * tables only group names that mean the same thing to a packager.
 */
static const char *const op_open[] = {
	"open", "openat", "openat2", "creat", NULL
};
static const char *const op_exec[] = {
	"execve", "execveat", "execv", NULL
};
static const char *const op_stat[] = {
	"stat", "stat64", "lstat", "lstat64", "newfstatat", "fstatat64",
	"statx", "statfs", "statfs64", "statmount", "access", "faccessat",
	"faccessat2", "readlink", "readlinkat", "uselib", NULL
};
static const char *const op_unlink[] = {
	"unlink", "unlinkat", "rmdir", NULL
};
static const char *const op_mkdir[] = {
	"mkdir", "mkdirat", NULL
};
static const char *const op_rename[] = {
	"rename", "renameat", "renameat2", NULL
};
static const char *const op_link[] = {
	"link", "linkat", NULL
};
static const char *const op_symlink[] = {
	"symlink", "symlinkat", NULL
};
static const char *const op_mknod[] = {
	"mknod", "mknodat", NULL
};
static const char *const op_chmod[] = {
	"chmod", "fchmodat", "fchmodat2", NULL
};
static const char *const op_chown[] = {
	"chown", "lchown", "chown32", "lchown32", "fchownat", NULL
};
static const char *const op_truncate[] = {
	"truncate", "truncate64", NULL
};
static const char *const op_xattr[] = {
	"setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr",
	"fremovexattr", NULL
};
static const char *const op_socket[] = {
	"connect", "bind", NULL
};
static const char *const op_chdir[] = {
	"chdir", NULL
};

struct op_group {
	const char *name;
	const char *const *syscalls;
};

static const struct op_group op_groups[] = {
	{ "open", op_open },
	{ "exec", op_exec },
	{ "stat", op_stat },
	{ "unlink", op_unlink },
	{ "mkdir", op_mkdir },
	{ "rename", op_rename },
	{ "link", op_link },
	{ "symlink", op_symlink },
	{ "mknod", op_mknod },
	{ "chmod", op_chmod },
	{ "chown", op_chown },
	{ "truncate", op_truncate },
	{ "xattr", op_xattr },
	{ "socket", op_socket },
	{ "chdir", op_chdir },
};

#define REPORT_OPS_MAX (int) ARRAY_SIZE(op_groups)

struct report_op {
	int group;		/* index into op_groups */
	unsigned long n;	/* total attempts */
	unsigned long ok;	/* successful attempts */
	unsigned long last_errno;
};

struct report_entry {
	struct report_entry *next;
	char *path;
	unsigned int hash;
	struct report_op ops[REPORT_OPS_MAX];
	unsigned int nops;
	pid_t first_pid;
	bool library;
};

#define REPORT_HASH_SIZE 8192
static struct report_entry *report_hash[REPORT_HASH_SIZE];
static unsigned long report_nentries;

static unsigned int
str_hash(const char *s)
{
	unsigned int h = 5381;

	while (*s)
		h = h * 33 + (unsigned char) *s++;
	return h;
}

static bool
path_looks_like_library(const char *path)
{
	const char *base = strrchr(path, '/');

	base = base ? base + 1 : path;
	return strstr(base, ".so") != NULL;
}

static struct report_op *
entry_get_op(struct report_entry *e, int group)
{
	for (unsigned int i = 0; i < e->nops; ++i)
		if (e->ops[i].group == group)
			return &e->ops[i];
	if (e->nops >= REPORT_OPS_MAX)
		return NULL;
	e->ops[e->nops].group = group;
	return &e->ops[e->nops++];
}

static void
report_note(const char *path, int group, pid_t pid, bool ok,
	    unsigned long err, bool unknown)
{
	const unsigned int h = str_hash(path) % REPORT_HASH_SIZE;
	struct report_entry *e;

	for (e = report_hash[h]; e; e = e->next)
		if (strcmp(e->path, path) == 0)
			break;
	if (!e) {
		e = xcalloc(1, sizeof(*e));
		e->path = xstrdup(path);
		e->hash = h;
		e->first_pid = pid;
		e->library = path_looks_like_library(path);
		e->next = report_hash[h];
		report_hash[h] = e;
		++report_nentries;
	}

	struct report_op *o = entry_get_op(e, group);
	if (!o)
		return;
	++o->n;
	if (unknown)
		return;		/* CONTINUEd by the seccomp backend */
	if (ok)
		++o->ok;
	else
		o->last_errno = err;
}

/* Called from syscall_exiting_trace() for every published syscall. */
void
file_report_note_syscall(struct tcb *tcp)
{
	if (!ext.report_files || tcp->ext_npaths == 0)
		return;

	const char *const name = tcp_sysent(tcp)->sys_name;

	for (int i = 0; i < REPORT_OPS_MAX; ++i)
		for (const char *const *p = op_groups[i].syscalls; *p; ++p)
			if (strcmp(*p, name) == 0) {
				for (unsigned int k = 0;
				     k < tcp->ext_npaths; ++k)
					report_note(tcp->ext_paths[k], i,
						     tcp->pid,
						     !tcp->u_error,
						     tcp->u_error,
						     tcp->ext_continued);
				return;
			}
}

static int
entry_cmp(const void *a, const void *b)
{
	const struct report_entry *const *ea = a;
	const struct report_entry *const *eb = b;

	return strcmp((*ea)->path, (*eb)->path);
}

static struct report_entry **
collect_entries(void)
{
	struct report_entry **arr;

	if (report_nentries == 0)
		return NULL;
	arr = xmalloc(report_nentries * sizeof(*arr));
	unsigned long j = 0;
	for (unsigned int i = 0; i < REPORT_HASH_SIZE; ++i)
		for (struct report_entry *e = report_hash[i]; e; e = e->next)
			arr[j++] = e;
	qsort(arr, report_nentries, sizeof(*arr), entry_cmp);
	return arr;
}

static bool
is_display_or_device_probe(const char *path)
{
	return strncmp(path, "/tmp/.X11-unix/", 15) == 0
	       || strncmp(path, "/dev/dri/", 9) == 0
	       || strncmp(path, "/dev/fb", 7) == 0
	       || strncmp(path, "/dev/snd/", 9) == 0
	       || strncmp(path, "/dev/video", 10) == 0
	       || strncmp(path, "/dev/accel/", 11) == 0;
}

static void
print_op_json(FILE *fp, const struct report_op *o, bool comma)
{
	const char *name = o->last_errno < nerrnos
			   ? errnoent[o->last_errno] : NULL;

	fprintf(fp, "%s\"%s\":{\"n\":%lu,\"ok\":%lu",
		comma ? "," : "", op_groups[o->group].name, o->n, o->ok);
	if (o->last_errno) {
		if (name)
			fprintf(fp, ",\"last_errno\":\"%s\"", name);
		else
			fprintf(fp, ",\"last_errno\":\"ERRNO_%lu\"",
				o->last_errno);
	}
	fputs("}", fp);
}

static void
file_report_dump_json(FILE *fp)
{
	struct report_entry **arr = collect_entries();

	fputs("{\"type\":\"file_report\",\"entries\":{", fp);
	if (arr) {
		for (unsigned long i = 0; i < report_nentries; ++i) {
			struct report_entry *e = arr[i];

			if (i)
				fputc(',', fp);
			ext_json_print_string(fp, e->path);
			fprintf(fp, ":{\"library\":%s,\"first_pid\":%d,"
				   "\"ops\":{", e->library ? "true" : "false",
				e->first_pid);
			for (unsigned int j = 0; j < e->nops; ++j)
				print_op_json(fp, &e->ops[j], j > 0);
			fputs("}}", fp);
		}
	}

	fputs("},\"hints\":[", fp);
	if (arr) {
		bool first = true;

		for (unsigned long i = 0; i < report_nentries; ++i) {
			struct report_entry *e = arr[i];
			unsigned long attempts = 0;

			for (unsigned int j = 0; j < e->nops; ++j)
				attempts += e->ops[j].n;
			if (attempts == 0)
				continue;
			if (is_display_or_device_probe(e->path)) {
				fprintf(fp, "%s{\"hint\":"
					   "\"missing_display_or_device\","
					   "\"path\":\"%s\",\"attempts\":%lu}",
					first ? "" : ",", e->path, attempts);
				first = false;
			}
		}
	}
	fputs("]}\n", fp);
	free(arr);
}

static void
file_report_dump_text(FILE *fp)
{
	struct report_entry **arr = collect_entries();

	fputs("# strace-appimage file report\n", fp);
	fputs("# PATH [L=library] OP(n/ok,last-errno)...\n", fp);
	if (arr) {
		for (unsigned long i = 0; i < report_nentries; ++i) {
			struct report_entry *e = arr[i];

			fprintf(fp, "%s%s\t", e->path,
				e->library ? " [L]" : "");
			for (unsigned int j = 0; j < e->nops; ++j) {
				const struct report_op *o = &e->ops[j];

				fprintf(fp, "%s%s(%lu/%lu",
					j ? " " : "",
					op_groups[o->group].name, o->n,
					o->ok);
				if (o->last_errno)
					fprintf(fp, ",E%lu", o->last_errno);
				fputs(")", fp);
			}
			fputc('\n', fp);
		}
	}
	free(arr);
}

void
file_report_dump(FILE *out_fp)
{
	FILE *fp = out_fp ?: shared_log;

	if (!ext.report_files)
		return;

	if (ext.json)
		file_report_dump_json(fp);
	else
		file_report_dump_text(fp);
}

void
file_report_free(void)
{
	for (unsigned int i = 0; i < REPORT_HASH_SIZE; ++i) {
		struct report_entry *e = report_hash[i];

		while (e) {
			struct report_entry *next = e->next;

			free(e->path);
			free(e);
			e = next;
		}
		report_hash[i] = NULL;
	}
	report_nentries = 0;
}
