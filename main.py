print('[...] loading...', end='', flush=True)

from hacking.network import _print_port_info
from rich.traceback import install
install(show_locals=True, width=300)

print('\r[...] starting...', end='\r', flush=True)

_print_port_info(port=13)
