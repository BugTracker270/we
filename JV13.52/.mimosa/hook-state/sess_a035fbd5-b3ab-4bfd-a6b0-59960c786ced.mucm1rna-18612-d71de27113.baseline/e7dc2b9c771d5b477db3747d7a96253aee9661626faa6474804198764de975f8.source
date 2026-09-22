txt = open(r'C:\Users\Kinan\Downloads\JV13.52\console_log_probe.txt',
           'rb').read().decode('utf-8', errors='replace')
L = txt.splitlines()
keys = ('trap', 'panic', 'fault', 'rip', 'fatal', 'excp', 'kill', 'core',
        'abort', '0xffffffff8', '0xffffffff9', '0xffffffffa')
print(f"{len(L)} lines in log\n")
shown = set()
for i, line in enumerate(L):
    low = line.lower()
    if any(k in low for k in ('trap', 'panic', 'fault', 'excp', 'abort', 'core dump')):
        for j in range(max(0, i - 2), min(len(L), i + 18)):
            if j not in shown:
                shown.add(j)
                print(f"{j:4}  {L[j][:190]}")
        print("-" * 70)
