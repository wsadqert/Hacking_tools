print('[...] loading...', end='', flush=True)

from hacking.network import print_port_info, port_scan
from rich.traceback import install
install(show_locals=True, width=300)

print('\r[...] starting...', end='\r', flush=True)
while True:
	print_port_info(port=int(input('enter port: ')))
# port_scan(host='8.8.8.8')

_print_port_info(port=13)

ports: list[int] = [i[0] for i in ports_info]

print(set(range(49152)) - set(ports))
"""