/*
 * unit_json_escape.c -- unit test for the shared JSON string escaper
 * (ext_json_print_string, strace/src/tracing_ext.c).  Includes the .c
 * file as a single translation unit so the static-free function is
 * reachable with minimal linkage.  Exits non-zero on the first mismatch.
 */
#include "tracing_ext.c"
#include <stdio.h>
#include <string.h>

static int failures;

static void
expect(const char *in, const char *want)
{
	char got[512];
	FILE *fp = fmemopen(got, sizeof(got), "w");

	ext_json_print_string(fp, in);
	fclose(fp);
	if (strcmp(got, want) != 0) {
		printf("FAIL: in=[%s] want=[%s] got=[%s]\n", in, want, got);
		++failures;
	} else {
		printf("ok:   [%s] -> %s\n", in, got);
	}
}

int
main(void)
{
	expect("plain", "\"plain\"");
	expect("with\"quote", "\"with\\\"quote\"");
	expect("back\\slash", "\"back\\\\slash\"");
	expect("tab\there", "\"tab\\there\"");
	expect("nl\nhere", "\"nl\\nhere\"");
	expect("cr\rhere", "\"cr\\rhere\"");
	expect("ctl\x01\x02", "\"ctl\\u0001\\u0002\"");
	expect("del\x7f", "\"del\\u007f\"");
	/* UTF-8 passes through byte-wise (documented behavior) */
	expect("caf\xc3\xa9", "\"caf\xc3\xa9\"");

	printf("%s: %d failures\n", failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}

/* Linkage stub: error_prints.c needs die(); provide a no-op for the test. */
void die(void) { _exit(1); }
