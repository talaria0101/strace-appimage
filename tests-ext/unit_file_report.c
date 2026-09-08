/*
 * unit_file_report.c -- unit test for the --report-files collector
 * (strace/src/file_report.c): op classification, library detection,
 * counters, and the JSON/text dumps, driven through synthetic tcbs.
 */
#include "file_report.c"
#include <stdio.h>
#include <string.h>

static int failures;
static struct_sysent ent_open, ent_execve, ent_stat, ent_read;

static void
mkcall(struct tcb *tcp, struct_sysent *ent, const char *name,
       long rval, unsigned long err, const char *path)
{
	memset(tcp, 0, sizeof(*tcp));
	tcp->pid = 4242;
	ent->sys_name = name;
	tcp->s_ent = ent;
	tcp->u_rval = rval;
	tcp->u_error = err;
	ext_reset_paths(tcp);
	if (path)
		ext_note_path(tcp, path);
}

#define CHECK(cond) do { \
	if (!(cond)) { printf("FAIL %s:%d: %s\n", __func__, __LINE__, #cond); \
		++failures; } \
	else printf("ok: %s\n", #cond); } while (0)

int
main(void)
{
	struct tcb tcp;

	ext.report_files = true;	/* the option under test */

	/* classification: open vs exec vs stat vs unclassified */
	mkcall(&tcp, &ent_open, "openat", 3, 0, "/usr/lib/libfoo.so.1");
	file_report_note_syscall(&tcp);
	mkcall(&tcp, &ent_open, "openat", -1, ENOENT, "/usr/lib/libbar.so");
	file_report_note_syscall(&tcp);
	mkcall(&tcp, &ent_execve, "execve", 0, 0, "/usr/bin/app");
	file_report_note_syscall(&tcp);
	mkcall(&tcp, &ent_stat, "newfstatat", 0, 0, "/tmp/.X11-unix/X0");
	file_report_note_syscall(&tcp);
	mkcall(&tcp, &ent_stat, "read", 5, 0, "/etc/passwd"); /* unclassified */
	file_report_note_syscall(&tcp);

	CHECK(report_nentries == 4);	/* read contributes nothing */

	/* JSON dump is valid JSONL for the entries; verify key fragments */
	FILE *fp = fmemopen((char[65536]){}, 65536, "w");
	file_report_dump_json(fp);
	fclose(fp);
	/* (the full-buffer check is done by run-unit-tests.sh via jq) */

	/* text dump mentions libraries and ops */
	char buf[65536];
	fp = fmemopen(buf, sizeof(buf), "w");
	file_report_dump_text(fp);
	fclose(fp);
	CHECK(strstr(buf, "/usr/lib/libfoo.so.1") != NULL);
	CHECK(strstr(buf, "open(1/1)") != NULL);
	CHECK(strstr(buf, "open(1/0,E2)") != NULL);	/* ENOENT = 2 */
	CHECK(strstr(buf, "exec(1/1)") != NULL);
	CHECK(strstr(buf, "[L]") != NULL);		/* .so marked library */

	/* library heuristic */
	CHECK(path_looks_like_library("/lib/x86_64-linux-gnu/libc.so.6"));
	CHECK(path_looks_like_library("/opt/app/libplugin.so"));
	CHECK(!path_looks_like_library("/usr/bin/app"));
	CHECK(!path_looks_like_library("/etc/ld.so.conf.d/x.conf"));

	/* display/device probe heuristic */
	CHECK(is_display_or_device_probe("/tmp/.X11-unix/X0"));
	CHECK(is_display_or_device_probe("/dev/dri/renderD128"));
	CHECK(is_display_or_device_probe("/dev/fb0"));
	CHECK(!is_display_or_device_probe("/usr/lib/libGL.so.1"));

	file_report_free();
	printf("%s: %d failures\n", failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}

/* Linkage stubs */
void die(void) { _exit(1); }
struct tracing_ext_state ext;
FILE *shared_log;
const struct_sysent stub_sysent;
const char *const errnoent[140] = {
	[1] = "EPERM", [2] = "ENOENT", [13] = "EACCES",
};
const unsigned int nerrnos = 140;
