print('[...] loading...', end='', flush=True)

from hacking.network import port_scan
from rich.traceback import install
install(show_locals=True, width=300)

print('\r[...] starting...', end='\r', flush=True)

port_scan(host='1.1.1.1')
