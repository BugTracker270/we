import time, datetime, re
from ftplib import FTP

LOG = r'C:\Users\Kinan\Downloads\JV13.52\monitor_usb.log'
POLL = 5
DURATION = 900          # 15 minutes

def snapshot():
    """Return a compact string of interesting files with sizes, or raise."""
    ftp = FTP()
    ftp.connect('172.20.10.3', 2121, timeout=8)
    ftp.login('anonymous', 'anonymous')
    lines = []
    ftp.retrlines('LIST /mnt/usb0', lines.append)
    ftp.quit()
    out = []
    for L in lines:
        # ls -l style: perms links owner group SIZE Mon DD YYYY name
        m = re.match(r'\S+\s+\S+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\d+\s+\S+\s+(.+)$', L)
        if not m:
            continue
        size, name = int(m.group(1)), m.group(2).strip()
        if name in ('.', '..') or name.startswith('System Volume'):
            continue
        if name == 'safe.PS4UPDATE.PUP':
            continue
        out.append('%s=%d' % (name, size))
    return ' | '.join(sorted(out)) if out else '(no interesting files)'

start = time.time()
last = None
with open(LOG, 'a', encoding='utf-8') as f:
    f.write("\n=== monitor v2 start %s ===\n" % datetime.datetime.now().isoformat(timespec='seconds'))
    f.flush()
    while time.time() - start < DURATION:
        stamp = datetime.datetime.now().strftime('%H:%M:%S')
        try:
            state = snapshot()
            line = '%s  FTP-OK    %s' % (stamp, state)
        except Exception as e:
            line = '%s  FTP-DEAD  (%s)' % (stamp, type(e).__name__)
            state = line
        if state != last:
            f.write(line + "\n")
            f.flush()
            last = state
        time.sleep(POLL)
    f.write("=== monitor v2 end %s ===\n" % datetime.datetime.now().isoformat(timespec='seconds'))
