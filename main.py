print('[...] loading...', end='', flush=True)

from hacking.network import print_port_info, port_scan
from rich.traceback import install
install(show_locals=True, width=300)

print('\r[...] starting...', end='\r', flush=True)
while True:
	print_port_info(port=int(input('enter port: ')))
# port_scan(host='8.8.8.8')

"""
with open("hacking/sources/ports_info.dat", 'rt', encoding='windows-1251') as f:
	ports_info = eval(f.read())

ports: list[int] = [i[0] for i in ports_info]

print(set(range(49152)) - set(ports))
"""