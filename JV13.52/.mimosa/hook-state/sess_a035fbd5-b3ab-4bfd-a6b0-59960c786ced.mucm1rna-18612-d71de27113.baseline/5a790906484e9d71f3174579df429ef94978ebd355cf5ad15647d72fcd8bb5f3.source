#!/usr/bin/env python3
"""Fetch sd_status.txt and sd_keys.txt - one RETR per fresh session.

Each file gets its own connection and exactly one RETR. No NLST/LIST/MLSD:
listing is what killed GoldHEN's FTP server before.
"""
import os, sys
from ftplib import FTP

HOSTS = ['172.20.10.3', '192.168.1.100', '192.168.0.100']
DEST = r'C:\Users\Kinan\Downloads\JV13.52'
FILES = ['/mnt/usb0/sd_status.txt', '/mnt/usb0/sd_keys.txt']


def hosts():
    for h in HOSTS:
        yield h


def one_retr(remote, local):
    data = bytearray()
    for h in hosts():
        try:
            f = FTP()
            f.encoding = 'latin-1'
            f.connect(h, 2121, timeout=20)
            try:
                f.login('anonymous', 'anonymous')
            except Exception:
                pass
            f.retrbinary('RETR ' + remote, data.extend, blocksize=8192)
            try:
                f.quit()
            except Exception:
                pass
            open(local, 'wb').write(bytes(data))
            return h, len(data)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            try:
                f.close()
            except Exception:
                pass
    print(f"  {remote}: FAILED ({err})")
    return None, 0


for remote in FILES:
    local = os.path.join(DEST, os.path.basename(remote))
    h, n = one_retr(remote, local)
    if h:
        print(f"  {os.path.basename(remote):18s} {n:6d} B  from {h}")
        if remote.endswith('.txt'):
            print('  ' + '-' * 60)
            for line in open(local, 'r', errors='replace').read().splitlines():
                print('  ' + line)
            print()
