/*
 * tracing_ext.c -- shared state and per-syscall capture helpers for the
 * strace-appimage tracing extensions (see tracing_ext.h).
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "tracing_ext.h"

#include <stdio.h>

/*
 * Print a JSON string literal (with the surrounding quotes) into fp,
 * escaping what must be escaped.  strace output can contain arbitrary
 * tracee bytes, so escape strictly per RFC 8259 and switch to \uXXXX
 * for anything not safely printable.  Shared by the --json event
 * emitter and the --report-files dump.
 */
void
ext_json_print_string(FILE *fp, const char *s)
{
	fputc('"', fp);
	for (const unsigned char *p = (const unsigned char *) s; *p; ++p) {
		switch (*p) {
		case '"':
			fputs("\\\"", fp);
			break;
		case '\\':
			fputs("\\\\", fp);
			break;
		case '\b':
			fputs("\\b", fp);
			break;
		case '\f':
			fputs("\\f", fp);
			break;
		case '\n':
			fputs("\\n", fp);
			break;
		case '\r':
			fputs("\\r", fp);
			break;
		case '\t':
			fputs("\\t", fp);
			break;
		default:
			if (*p < 0x20 || *p == 0x7f)
				fprintf(fp, "\\u%04x", *p);
			else
				fputc(*p, fp);
		}
	}
	fputc('"', fp);
}

void
ext_reset_paths(struct tcb *tcp)
{
	for (unsigned int i = 0; i < tcp->ext_npaths && i < EXT_MAX_PATHS_PER_SYSCALL; ++i) {
		free(tcp->ext_paths[i]);
		tcp->ext_paths[i] = NULL;
	}
	tcp->ext_npaths = 0;
}

void
ext_note_path(struct tcb *tcp, const char *path)
{
	if (tcp->ext_npaths >= EXT_MAX_PATHS_PER_SYSCALL)
		return;
	tcp->ext_paths[tcp->ext_npaths++] = xstrdup(path);
}

void
ext_reset_notes(struct tcb *tcp)
{
	for (unsigned int i = 0; i < tcp->ext_nnotes && i < EXT_MAX_NOTES_PER_SYSCALL; ++i) {
		free(tcp->ext_notes[i]);
		tcp->ext_notes[i] = NULL;
	}
	tcp->ext_nnotes = 0;
}

void
ext_add_note(struct tcb *tcp, const char *note)
{
	if (tcp->ext_nnotes >= EXT_MAX_NOTES_PER_SYSCALL)
		return;
	tcp->ext_notes[tcp->ext_nnotes++] = xstrdup(note);
}

const char *
ext_notes_joined(struct tcb *tcp, char sep)
{
	static char buf[256];
	size_t off = 0;

	buf[0] = '\0';
	for (unsigned int i = 0; i < tcp->ext_nnotes; ++i) {
		if (i) {
			if (off + 1 >= sizeof(buf))
				break;
			buf[off++] = sep;
			buf[off] = '\0';
		}
		size_t l = strlen(tcp->ext_notes[i]);
		if (off + l >= sizeof(buf))
			l = sizeof(buf) - 1 - off;
		memcpy(buf + off, tcp->ext_notes[i], l);
		off += l;
		buf[off] = '\0';
	}
	return buf;
}

/* Free everything a tcb holds for the extensions; called from droptcb(). */
void
ext_free_tcb(struct tcb *tcp)
{
	ext_reset_paths(tcp);
	ext_reset_notes(tcp);
}
