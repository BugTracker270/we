import time, hashlib, os, sys
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
REMOTE = '/mnt/usb0/PS4UPDATE1.PUP.dec'
LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\dec\PS4UPDATE1.PUP.dec'
os.makedirs(os.path.dirname(LOCAL), exist_ok=True)

state = {'n': 0, 't0': time.time(), 'last': 0}
def cb(chunk):
    f.write(chunk)
    state['n'] += len(chunk)
    if state['n'] - state['last'] >= 20*1024*1024:
        state['last'] = state['n']
        el = time.time() - state['t0']
        print("  %8.1f MB  (%.2f MB/s)" % (state['n']/1048576, state['n']/1048576/el), flush=True)

ftp = FTP(); ftp.connect(HOST, PORT, timeout=30); ftp.login('anonymous','anonymous')
print("downloading", REMOTE, "->", LOCAL, flush=True)
t0 = time.time()
with open(LOCAL, 'wb') as f:
    ftp.retrbinary('RETR ' + REMOTE, cb, blocksize=65536)
ftp.quit()
el = time.time() - t0
size = os.path.getsize(LOCAL)
print("done: %s bytes in %.1fs (%.2f MB/s)" % (format(size, ','), el, size/1048576/el))
h = hashlib.sha256(open(LOCAL,'rb').read()).hexdigest()
print("sha256:", h)
