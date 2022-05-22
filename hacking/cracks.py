import os
from tqdm import tqdm
from .__init__ import wordlist

import pikepdf
from zipfile import ZipFile
from rarfile import RarFile
from py7zr import SevenZipFile

from lzma import LZMAError


def crack_pdf(filename: str):
	for password in tqdm(wordlist, "Cracking PDF"):
		try:
			with pikepdf.open(filename, password=password):
				print("[+] Password found:", password)
				break
		except pikepdf.PasswordError:
			continue
	else:
		print("[!] Password not found, try other wordlist")


def crack_archive(filename: str, fmt: str = ''):
	"""7z cracking is very slow!"""

	path = os.path.split(os.path.abspath(filename))[0]

	def crack_zip(filename: str):
		file: ZipFile = ZipFile(filename)

		for word in tqdm(wordlist, "Cracking ZIP"):
			try:
				file.extractall(path=path, pwd=word.strip())
				print("[+] Password found:", word.decode().strip())
				break
			except RuntimeError:
				continue
		else:
			print("[!] Password not found, try other wordlist")

	def crack_rar(filename: str):
		file: RarFile = RarFile(filename)

		for word in tqdm(wordlist, "Cracking RAR"):
			try:
				file.extractall(path=path, pwd=word.strip())
				print("[+] Password found:", word.decode().strip())
				break
			except RuntimeError:
				continue
		else:
			print("[!] Password not found, try other wordlist")

	def crack_7z(filename: str):
		"""Very slow!"""
		for word in tqdm(wordlist, "Cracking 7Z"):
			try:
				with SevenZipFile(filename, password=word.strip().decode("utf-8")) as file:
					file.extractall(path=path)

				print("[+] Password found:", word.decode().strip())
				break
			except LZMAError:
				continue
		else:
			print("[!] Password not found, try other wordlist")

	if not fmt:
		fmt: str = filename.split('.')[-1]
		pass

	match fmt:
		case 'zip':
			crack_zip(filename)
		case 'rar':
			crack_rar(filename)
		case '7z':
			crack_7z(filename)
		case _:
			raise RuntimeError('Unsupported archive type')
