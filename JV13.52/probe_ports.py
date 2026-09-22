"""Probe the console for a remote payload-execution service.

  9020  classic PS4 payload injector port (netcat-style)
  9021  alt payload port
  3232  GoldHEN web/API (some builds)
  9090  common host-tool HTTP
  1337 / 5000 / 8080  misc
  2121  GoldHEN FTP (known good)
"""
import socket

HOST = '172.20.10.3'
PORTS = [2121, 9020, 9021, 3232, 9090, 1337, 5000, 8080, 80, 21, 22, 755, 12800]

print(f"probing {HOST}\n")
open_ports = []
for p in PORTS:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        s.connect((HOST, p))
        open_ports.append(p)
        banner = b""
        try:
            s.settimeout(1.5)
            banner = s.recv(120)
        except Exception:
            pass
        print(f"  {p:6} OPEN   banner={banner[:100]!r}")
    except Exception as e:
        print(f"  {p:6} closed ({type(e).__name__})")
    finally:
        s.close()

print("\nopen:", open_ports)
