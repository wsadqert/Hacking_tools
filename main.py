from hacking.network import port_scan

from rich.traceback import install
install(show_locals=True, width=300)

port_scan('192.168.0.1')
