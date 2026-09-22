#!/usr/bin/env python3
"""Replace the bogus SELF-magic check with a structural validity check.

Every SELF in dec/ starts with 4f153d1d (0x1d3d154f), not 0x00454353, so the
"SCE" check rejected a good file. Run 1 worked only because it predated it.
"""
import sys

SRC = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\source\main.c'
NEW = """    /*
     * DO NOT test for a SELF magic here.
     *
     * Every SELF in dec/ (80010008, 80010002, the 14.00 kernel, orbis_swu)
     * begins with 4f153d1d = 0x1d3d154f, NOT the textbook SELF magic
     * 0x00454353. An "SCE" check I added for robustness therefore rejected a
     * perfectly good file and cost two runs; run 1 worked only because it
     * predated that check. Validity is established structurally instead - the
     * geometry tests below reject anything whose header does not chain
     * coherently within the file.
     */
    if (self && self_size < 0x100) {
        printf_notification("selfdec2: target.self too small");
        free(self);
        self = 0;
        self_size = 0;
    }"""

OLD = """    if (self && !(self[0] == 'S' && self[1] == 'C' && self[2] == 'E')) {
        printf_notification("selfdec2: target.self is not a SELF");
        free(self);
        self = 0;
        self_size = 0;
    }"""

src = open(SRC, encoding='utf-8').read()
if OLD not in src:
    print("FAIL: magic block not found verbatim")
    sys.exit(2)
if src.count(OLD) != 1:
    print(f"FAIL: magic block appears {src.count(OLD)} times")
    sys.exit(2)

src = src.replace(OLD, NEW)
open(SRC, 'w', encoding='utf-8', newline='').write(src)

chk = open(SRC, encoding='utf-8').read()
assert 'is not a SELF' not in chk, "old check still present"
assert 'target.self too small' in chk
print("PASS: magic check replaced with structural size check")
