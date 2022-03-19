print('[...] loading...', end='', flush=True)

from hacking.network import port_scan
from rich.traceback import install
install(show_locals=True, width=300)

print('\r[...] starting...', end='', flush=True)

port_scan('192.168.0.1')
