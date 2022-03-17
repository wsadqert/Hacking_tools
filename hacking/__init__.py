from astropy.utils.data import download_file
from shutil import move
wordlist = "./hacking/sources/rockyou.txt"

try:
	with open(wordlist):
		pass
except FileNotFoundError:
	download_file("https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
	move('./hacking/rockyou.txt', wordlist)

'''
from .network import *
from .cracks import *
from .crypt import *
from .data_collecting import *
'''