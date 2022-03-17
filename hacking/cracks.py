from typing import *
import pikepdf
from tqdm import tqdm
from zipfile import ZipFile
from rarfile import RarFile
from .__init__ import wordlist


def crack_pdf(filename: str):
	for password in tqdm(wordlist, "Decrypting PDF"):
		try:
			with pikepdf.open(filename, password=password) as pdf:
				print("[+] Password found:", password)
				break
		except pikepdf.PasswordError:
			continue

	print("[!] Password not found, try other wordlist")


def crack_archive(filename: str, type: Union[str, None]):
	def crack_zip(filename: str):
		file: ZipFile = ZipFile(filename)

		for word in tqdm(wordlist, "Cracking PDF"):
			try:
				file.extractall(pwd=word.strip())
				print("[+] Password found:", word.decode().strip())
				break
			except RuntimeError:
				continue

		print("[!] Password not found, try other wordlist")

	def crack_rar(filename: str):
		file: RarFile = RarFile(filename)

		for word in tqdm(wordlist, "Cracking PDF"):
			try:
				file.extractall(pwd=word.strip())
				print("[+] Password found:", word.decode().strip())
				break
			except RuntimeError:
				continue

		print("[!] Password not found, try other wordlist")

	if type and filename.endswith(type):
		match type:
			case 'zip':
				crack_zip(filename)
			case 'rar':
				crack_rar(filename)
			case _:
				pass
