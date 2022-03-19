from astropy.utils.data import download_file
from shutil import move

from typing import Union
from os import PathLike


PATH: type = Union[str, bytes, PathLike[str], PathLike[bytes]]
url: str = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
wordlist_path: PATH = "./hacking/sources/rockyou.txt"

try:
	with open(wordlist_path):
		pass
except FileNotFoundError:
	path: str = download_file(url, cache=True)
	move(path, wordlist_path)

with open(wordlist_path, 'rb') as f:
	wordlist: list[PATH] = [i.strip(b'\n ') for i in f.readlines()]

'''
from .network import *
from .cracks import *
from .crypt import *
from .data_collecting import *
'''