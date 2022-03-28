print('[...] loading...', end='', flush=True)

from hacking.network import extract_links
from rich.traceback import install
install(show_locals=True, width=300)

print('\r[...] starting...', end='\r', flush=True)

print(extract_links(max_urls=1))
