from hacking.network import *
from rich.traceback import install

install(show_locals=True, width=300)

port_scan('172.20.120.103')
