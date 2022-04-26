import os.path

from astropy.utils.data import download_file
from shutil import move

from typing import Union, Final
from os import PathLike


PATH: Final[type] = Union[str, bytes, PathLike[str], PathLike[bytes]]
url: Final[str] = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
wordlist_path: Final[PATH] = "./hacking/sources/rockyou.txt"

if not os.path.exists(wordlist_path):
	path: PATH = download_file(url, cache=True)
	move(path, wordlist_path)

with open(wordlist_path, 'rb') as f:
	wordlist: Final[list[PATH]] = [i.strip(b'\n ') for i in f.readlines()]
