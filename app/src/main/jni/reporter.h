#pragma once

/* The exploit binary prints to stdout; the reporter keeps the call shape the
 * shared exploit sources already use. */
struct Reporter { int unused; };

void reportfmt(struct Reporter *r, const char *fmt, ...) __attribute__((__format__(printf, 2, 3)));
#define REPORTLN(fmt, ...) reportfmt(reporter, fmt "\n" __VA_OPT__(,) __VA_ARGS__)
