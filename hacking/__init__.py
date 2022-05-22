import os.path

from astropy.utils.data import download_file
from shutil import move

from typing import Final
from os import PathLike

from pydantic import AnyHttpUrl, AnyUrl, FileUrl, HttpUrl

PATH: Final[type] = str | bytes | PathLike[str] | PathLike[bytes]
URL: Final[type] = str | AnyHttpUrl[str] | AnyUrl[str] | FileUrl[str] | HttpUrl[str]

url: Final[str] = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
wordlist_path: Final[PATH] = "./hacking/sources/rockyou.txt"

if not os.path.exists(wordlist_path):
	path: PATH = download_file(url, cache=True)
	move(path, wordlist_path)

with open(wordlist_path, 'rb') as f:
	wordlist: Final[list[PATH]] = [i.strip(b'\n ') for i in f.readlines()]
