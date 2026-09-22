#!/usr/bin/env python3
"""Quick presence probe for the bug classes flagged in the handoff.

This is NOT the audit - it is a 10-second orientation that tells you which
subsystems are even present as named strings, so you know where to aim first.
"""
IMG = r'C:\Users\Kinan\Downloads\JV13.52\1352-KERNEL-HANDOFF\kmemfull.bin'
d = open(IMG, 'rb').read()

GROUPS = {
    'rtsock family (CVE-2026-3038 class, unprivileged RTM_GET)': [
        b'rtsock', b'rtsock_msg_buffer', b'RTM_GET', b'route_output',
        b'PRIV_NET_ROUTE', b'rt_msg', b'sa_len',
    ],
    'the KNOWN Poops chain surface (already patched - avoid)': [
        b'ip6_pktopts', b'IPV6_RTHDR', b'ip6_setpktopts', b'ip6_getpkt',
        b'kqueue', b'kq_lock', b'knote',
    ],
    'generic UAF / overflow hunting grounds': [
        b'copyin', b'copyout', b'uio', b'iov', b'sendmsg', b'recvmsg',
        b'msgsnd', b'pipe', b'kevent', b'devfs', b'msdosfs', b'exfat',
    ],
    'SBL / AuthMgr (named in our symbol recovery)': [
        b'sceSblAuthMgrIsLoadable', b'verifyHeader', b'decryptSelfBlock',
        b'loadSelfSegment', b'80010008', b'SblDrvHdlrSx',
    ],
    'syscall / privilege plumbing': [
        b'sysent', b'nosys', b'priv_check', b'suser', b'p_candebug',
    ],
}

print(f'image {len(d)} bytes\n')
for title, needles in GROUPS.items():
    print('=' * 72)
    print(title)
    print('=' * 72)
    for n in needles:
        hits = []
        off = d.find(n)
        while off != -1 and len(hits) < 4:
            hits.append(off)
            off = d.find(n, off + 1)
        print(f'  {n.decode():<26} {"absent" if not hits else "  ".join(hex(h) for h in hits)}')
    print()
