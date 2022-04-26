import string
import subprocess
from re import Pattern

import regex as re
import os
from requests import Response
from colorama import init as colorama_init, Fore

from pydantic import AnyHttpUrl
from requests_html import HTMLSession, MaxRetries
from tqdm import tqdm
from typing import Iterable

colorama_init()

GREEN: str = Fore.GREEN
GRAY: str = Fore.LIGHTBLACK_EX
RESET: str = Fore.RESET
RED: str = Fore.RED
YELLOW: str = Fore.YELLOW


async def render(response):
	try:
		await response.html.arender()
	except MaxRetries:
		pass


def get_random_mac() -> str:
	"""Generate and return a MAC address in the format of WINDOWS"""
	import random

	# get the hexdigits uppercased
	uppercased_hexdigits = ''.join(set(string.hexdigits.upper()))
	# 2nd character must be 2, 4, A, or E
	return random.choice(uppercased_hexdigits) + random.choice("24AE") + "".join(random.sample(uppercased_hexdigits, k=10))


def randomize_mac_address():
	network_interface_reg_path: str = r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
	transport_name_regex: Pattern = re.compile("{.+}")
	mac_regex: Pattern = re.compile(r"([A-Z0-9]{2}[:-]){5}([A-Z0-9]{2})")

	def clean_mac(mac: str) -> str:
		"""Simple function to clean non-hexadecimal characters from a MAC address
		mostly used to remove '-' and ':' from MAC addresses and also uppercase it"""
		return "".join(c for c in mac if c in string.hexdigits).upper()

	def get_connected_adapters_mac_address() -> list[tuple]:
		# make a list to collect connected adapter's MAC addresses along with the transport name
		connected_adapters_mac = []
		# use the getmac command to extract
		for potential_mac in subprocess.check_output("getmac").decode().splitlines():
			# parse the MAC address from the line
			mac_address = mac_regex.search(potential_mac)
			# parse the transport name from the line
			transport_name = transport_name_regex.search(potential_mac)
			if mac_address and transport_name:
				# if a MAC and transport name are found, add them to our list
				connected_adapters_mac.append((mac_address.group(), transport_name.group()))
		return connected_adapters_mac

	def get_user_adapter_choice(connected_adapters_mac):
		# print the available adapters
		for i, option in enumerate(connected_adapters_mac):
			print(f"#{i}: {option[0]}, {option[1]}")
		if len(connected_adapters_mac) <= 1:
			# when there is only one adapter, choose it immediately
			return connected_adapters_mac[0]
		# prompt the user to choose a network adapter index
		try:
			choice = int(input("Please choose the interface you want to change the MAC address:"))
			# return the target chosen adapter's MAC and transport name that we'll use later to search for our adapter
			# using the reg QUERY command
			return connected_adapters_mac[choice]
		except:
			# if -for whatever reason- an error is raised, just quit the script
			print("Not a valid choice, quitting...")
			exit()

	def change_mac_address(adapter_transport_name, new_mac_address):
		# use reg QUERY command to get available adapters from the registry
		output: str = subprocess.check_output(f"reg QUERY " + network_interface_reg_path.replace("\\\\", "\\")).decode()
		
		for interface in re.findall(rf"{network_interface_reg_path}\\\d+", output):
			# get the adapter index
			adapter_index = int(interface.split("\\")[-1])
			interface_content: str = subprocess.check_output(f"reg QUERY {interface.strip()}").decode()

			if adapter_transport_name in interface_content:
				# if the transport name of the adapter is found on the output of the reg QUERY command
				# then this is the adapter we're looking for
				# change the MAC address using reg ADD command
				changing_mac_output = subprocess.check_output(f"reg add {interface} /v NetworkAddress /d {new_mac_address} /f").decode()
				# print the command output
				print(changing_mac_output)
				# break out of the loop as we're done
				break

		return adapter_index

	def disable_adapter(adapter_index: int) -> str:
		# use wmic command to disable our adapter so the MAC address change is reflected
		return subprocess.check_output(f"wmic path win32_networkadapter where index={adapter_index} call disable").decode()

	def enable_adapter(adapter_index: int) -> str:
		# use wmic command to enable our adapter so the MAC address change is reflected
		return subprocess.check_output(f"wmic path win32_networkadapter where index={adapter_index} call enable").decode()

	if input('do you want to randomize mac? (y/n)').lower() == 'y':
		new_mac_address = get_random_mac()
	else:
		new_mac_address = input('enter new mac: ')

	connected_adapters_mac: list[tuple] = get_connected_adapters_mac_address()
	old_mac_address, target_transport_name = get_user_adapter_choice(connected_adapters_mac)

	print("[*] Old MAC address:", old_mac_address)
	
	adapter_index = change_mac_address(target_transport_name, new_mac_address)
	print("[+] Changed to:", new_mac_address)
	
	disable_adapter(adapter_index)
	print("[+] Adapter is disabled")
	
	enable_adapter(adapter_index)
	print("[+] Adapter is enabled again")


def print_port_info(port: int) -> None:
	if port not in range(0, 65537):
		print(f'{RED}Not a port!{RESET}')
		return
	
	with open("./hacking/sources/ports_info.dat", 'rt', encoding='windows-1251') as f:
		ports_info = eval(f.read())
	with open("./hacking/sources/ports_threat.dat", 'rt', encoding='windows-1251') as f:
		ports_threat_info = eval(f.read())

	ports: list[int] = [i[0] for i in ports_info]
	info: list[str] = [i[1] for i in ports_info]
	ports_threat: list[int] = [i[0] for i in ports_threat_info]
	info_threat: list[str] = [i[1] for i in ports_threat_info]

	indexes: list[int] = [i for i, x in enumerate(ports) if x == port]
	indexes_threat: list[int] = [i for i, x in enumerate(ports_threat) if x == port]

	print(f'Information about port {GREEN}{port}{RESET}:')

	if not indexes and not indexes_threat:
		print(f'{RED}No information!{RESET}')
		return
	
	for i in indexes:
		print('-', info[i])
	for i in indexes:
		print(f'-{RED}', info_threat[i], RESET)


def port_scan(host: str) -> set[int]:
	from queue import Queue
	from threading import Thread, Lock
	import socket
	from time import time

	t0: float = time()

	N_THREADS: int = 1000
	q: Queue[int] = Queue()
	print_lock: Lock = Lock()

	# parse_wiki()
	
	with open("./hacking/sources/ports_info.dat", 'rt', encoding='windows-1251') as f:
		ports_info = eval(f.read())
	with open("./hacking/sources/ports_threat.dat", 'rt', encoding='windows-1251') as f:
		ports_threat_info = eval(f.read())
	
	ports: list[int] = [i[0] for i in ports_info]
	info: list[str] = [i[1] for i in ports_info]
	ports_threat: list[int] = [i[0] for i in ports_threat_info]
	info_threat: list[str] = [i[1] for i in ports_threat_info]
	
	opened: set[int] = set()

	def scan_port(host: str, port: int):
		s = socket.socket()
		try:
			s.connect((host, port))
		except socket.error:
			print(f'\rfound {len(opened)} opened ports', end='', flush=True)
			pass
		else:
			opened.add(port)
		finally:
			s.close()

	def scan_thread(host: str):
		while True:
			worker = q.get()
			scan_port(host, worker)
			q.task_done()

	def main(host: str, ports: Iterable[int]):
		for t in tqdm(range(N_THREADS)):
			t = Thread(target=scan_thread, args=(host,))
			t.daemon = True
			t.start()

		for worker in tqdm(ports):
			q.put(worker)

		q.join()

	main(host, ports)
	t1: float = time()
	
	for port in sorted(opened):
		with print_lock:
			indexes: list[int] = [i for i, x in enumerate(ports) if x == port]
			indexes_threat: list[int] = [i for i, x in enumerate(ports_threat) if x == port]
			
			if not indexes and not indexes_threat:
				print(f'{RED}No information!{RESET}')
				continue
			
			print(f"\r{GREEN}{host:15}:{port:5} is opened {RESET}- {info[indexes[0]]}")
			
			for index in indexes[1:]:
				print(' ' * (len(f"\r{GREEN}{host:15}:{port:5} is opened {RESET}") - 11), end='')
				print('-', info[index])
			for index in indexes_threat:
				print(' ' * 31, f'-{RED}', info_threat[index], RESET)

	print(f'finished (found {len(opened)} opened ports)')

	print(f'{round(t1 - t0, 4)} s')
	
	return opened


def saved_wifi_passwords() -> None:
	from collections import namedtuple

	Profile: type = namedtuple("Profile", ["ssid", "ciphers", "key"])

	def get_saved_ssids() -> list[str]:
		"""Returns a list of saved SSIDs in a Windows machine using netsh command"""
		# get all saved profiles in the PC
		output: str = subprocess.check_output("netsh wlan show profiles").decode()
		ssids: list[str] = []
		profiles: list[str] = re.findall(r"All User Profile\s(.*)", output)
		for profile in profiles:
			# for each SSID, remove spaces and colon
			ssid = profile.strip().strip(":").strip()
			# add to the list
			ssids.append(ssid)
		return ssids

	def get_saved_wifi_passwords(verbose: bool = True) -> list[Profile]:
		"""Extracts saved Wi-Fi passwords saved in a Windows machine, this function extracts data using netsh
		command in Windows
		Args:
			verbose (int, optional): whether to print saved profiles real-time. Defaults to 1.
		Returns:
			[list]: list of extracted profiles, a profile has the fields ["ssid", "ciphers", "key"]
		"""
		ssids: list[str] = get_saved_ssids()
		profiles: list[Profile] = []
		for ssid in ssids:
			ssid_details: str = subprocess.check_output(f'netsh wlan show profile "{ssid}" key=clear').decode()
			# get the ciphers
			ciphers: list[str] = re.findall(r"Cipher\s(.*)", ssid_details)
			# clear spaces and colon
			ciphers: str = "/".join([c.strip().strip(":").strip() for c in ciphers])
			# get the Wi-Fi __password
			key: list[str] = re.findall(r"Key Content\s(.*)", ssid_details)
			# clear spaces and colon
			try:
				key: str = key[0].strip().strip(':').strip()
			except IndexError:
				key: str = 'None'
			profile: Profile = Profile(ssid=ssid, ciphers=ciphers, key=key)
			if verbose:
				print(f"{profile.ssid:25}{profile.ciphers:15}{profile.key:50}")
			profiles.append(profile)
		return profiles

	def print_profiles(verbose: bool = True):
		if os.name == "nt":
			print("SSID                     CIPHER(S)      KEY")
			get_saved_wifi_passwords(verbose)
		else:
			raise NotImplemented("Code only works for Windows")

	print_profiles()

	return


def saved_chrome_passwords() -> None:
	import json
	import base64
	import sqlite3
	import win32crypt
	from Crypto.Cipher import AES
	import shutil
	from datetime import datetime, timedelta

	def get_chrome_datetime(chromedate) -> datetime:
		"""Return a `datetime.datetime` object from a chrome format datetime
		Since `chromedate` is formatted as the number of microseconds since January 1601"""
		return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

	def get_encryption_key():
		local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
		with open(local_state_path, "r", encoding="utf-8") as f:
			local_state = f.read()
			local_state = json.loads(local_state)

		# decode the encryption key from Base64
		key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
		# remove DPAPI str
		key = key[5:]
		# return decrypted key that was originally encrypted
		# using a session key derived from current user's logon credentials
		# doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
		return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

	def decrypt_password(password, key) -> str:
		try:
			iv = password[3:15]
			password = password[15:]
			cipher = AES.new(key, AES.MODE_GCM, iv)
			return cipher.decrypt(password)[:-16].decode()
		except:
			try:
				return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
			except:
				# not supported
				return ''

	key = get_encryption_key()
	# local sqlite Chrome database path
	db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
	# copy the file to another location
	# as the database will be locked if chrome is currently running
	filename = "ChromeData.db"
	shutil.copyfile(db_path, filename)
	db = sqlite3.connect(filename)
	cursor = db.cursor()
	cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")

	for row in cursor.fetchall():
		origin_url, action_url, username, _, date_created, date_last_used = row
		password = decrypt_password(row[3], key)

		if username or password:
			print(f"Origin URL: {origin_url}")
			print(f"Action URL: {action_url}")
			print(f"Username: {username}")
			print(f"Password: {password}")
		else:
			continue

		if date_created != 86_400_000_000 and date_created:
			print(f"Creation date: {str(get_chrome_datetime(date_created))}")
		if date_last_used != 86_400_000_000 and date_last_used:
			print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")

		print("=" * 50)

	cursor.close()
	db.close()
	
	try:
		os.remove(filename)
	except (IsADirectoryError, FileNotFoundError, OSError):
		pass

	return


def extract_emails(url: AnyHttpUrl = "https://www.randomlists.com/email-addresses") -> list[str]:
	EMAIL_REGEX = r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"""

	session: HTMLSession = HTMLSession()
	response: Response = session.get(url)
	render(response)

	ans: list[str] = [re_match.group() for re_match in re.finditer(EMAIL_REGEX, response.html.raw_html.decode())]
	return ans


def extract_links(url: AnyHttpUrl = "https://www.randomlists.com/email-addresses", max_urls: int = 30) -> tuple[set[str], set[str]]:
	from urllib.parse import urlparse, urljoin, ParseResult
	from bs4 import BeautifulSoup
	from typing import Union

	internal_urls: set = set()
	external_urls: set = set()

	max_urls -= 1

	global total_urls_visited
	total_urls_visited = 0

	def is_valid(url: AnyHttpUrl) -> bool:
		"""Checks whether `url` is a valid URL."""
		parsed: ParseResult = urlparse(url)
		return bool(parsed.netloc and parsed.scheme)

	def get_all_website_links(url: AnyHttpUrl) -> set[str]:
		"""Returns all URLs that is found on `url` in which it belongs to the same website"""

		urls: set = set()
		domain_name: str = urlparse(url).netloc
		session: HTMLSession = HTMLSession()
		response: Response = session.get(url)

		render(response)

		soup = BeautifulSoup(response.html.html, 'html.parser')
		for a_tag in soup.findAll('a'):
			href = a_tag.attrs.get('href')
			if not href:
				continue

			# join the URL if it's relative link
			href = urljoin(url, href)
			parsed_href = urlparse(href)
			# remove URL GET parameters, URL fragments, etc.
			href = parsed_href.scheme + '://' + parsed_href.netloc + parsed_href.path

			if not is_valid(href):
				continue
			if href in internal_urls:
				continue
			if domain_name not in href:
				# external link
				if href not in external_urls:
					print(f"{GRAY}[!] External link: {href}{RESET}")
					external_urls.add(href)
				continue
			print(f"{GREEN}[*] Internal link: {href}{RESET}")
			urls.add(href)
			internal_urls.add(href)
		return urls

	def crawl(url: Union[AnyHttpUrl, str], max_urls:  int):
		"""
		Crawls a web page and extracts all links.
		You'll find all links in `external_urls` and `internal_urls` global set variables.
		:type url: Union[AnyHttpUrl, str]
		:param max_urls: number of max urls to crawl
		:type max_urls: int
		"""
		global total_urls_visited
		total_urls_visited += 1
		print(f"{YELLOW}[*] Crawling: {url}{RESET}")
		links: set[str] = get_all_website_links(url)
		for link in links:
			if total_urls_visited > max_urls:
				break
			crawl(link, max_urls=max_urls)

	crawl(url, max_urls=max_urls)

	print("[+] Total Internal links:", len(internal_urls))
	print("[+] Total External links:", len(external_urls))
	print("[+] Total URLs:", len(external_urls) + len(internal_urls))
	print("[+] Total crawled URLs:", max_urls + 1)

	return internal_urls, external_urls
