import os
import random
import socket
import string
import subprocess
from queue import Queue
from threading import Lock, Thread
from time import time
from urllib.parse import ParseResult, urljoin, urlparse

import re
from bs4 import BeautifulSoup
from requests import Response
from requests_html import HTMLSession, MaxRetries
from tqdm import tqdm

from hacking import URL
from constants import *


async def render(response) -> None:
	try:
		await response.html.arender()
	except MaxRetries:
		pass


def generate_random_mac() -> str:
	"""Generate and return a MAC address in the format of WINDOWS"""
	# get the hexdigits uppercased
	uppercased_hexdigits = ''.join(set(string.hexdigits.upper()))
	# 2nd character must be 2, 4, A, or E
	return random.choice(uppercased_hexdigits) + random.choice("24AE") + "".join(random.sample(uppercased_hexdigits, k=10))


# D4-1B-81-EC-6A-09
def randomize_mac_address() -> None:
	t0 = time()
	network_interface_reg_path: Final = r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
	transport_name_regex = re.compile("{.+}")
	mac_regex = re.compile(r"([A-Z0-9]{2}[:-]){5}([A-Z0-9]{2})")

	def get_connected_adapters_mac_address() -> list[tuple[str, str]]:  # make a list to collect connected adapter's MAC addresses along with the transport name
		connected_adapters_mac: list[tuple] = []
		for potential_mac in subprocess.check_output("getmac").decode().splitlines():  # use the getmac command to extract
			mac_address = mac_regex.search(potential_mac)  # parse the MAC address from the line
			transport_name = transport_name_regex.search(potential_mac)  # parse the transport name from the line
			if mac_address and transport_name:
				connected_adapters_mac.append((mac_address.group(), transport_name.group()))  # if a MAC and transport name are found, add them to our list
		return connected_adapters_mac

	def get_user_adapter_choice(connected_adapters_mac: Sequence[Sequence[str]], prompt: bool = False) -> Sequence[str]:
		for i, option in enumerate(connected_adapters_mac):  # print the available adapters
			print(f"#{i}: {option[0]}, {option[1]}")
		if len(connected_adapters_mac) == 1:
			# when there is only one adapter, choose it immediately
			return connected_adapters_mac[0]
		# prompt the user to choose a network adapter index
		try:
			choice = int(input("Please choose the interface you want to change the MAC address:")) if prompt else 0
			return connected_adapters_mac[choice]
		except (ValueError, IndexError):
			print("Not a valid choice, quitting...")
			exit()

	def change_mac_address(adapter_transport_name: str, new_mac_address: str) -> int:
		# use reg QUERY command to get available adapters from the registry
		output: str = subprocess.check_output(f"reg QUERY " + network_interface_reg_path.replace("\\\\", "\\")).decode()
		
		for interface in re.findall(rf"{network_interface_reg_path}\\\d+", output):
			# get the adapter index
			adapter_index: int = int(interface.split("\\")[-1])
			interface_content: str = subprocess.check_output(f"reg QUERY {interface.strip()}").decode()

			if adapter_transport_name in interface_content:
				# if the transport name of the adapter is found on the output of the reg QUERY command
				# then this is the adapter we're looking for
				# change the MAC address using reg ADD command
				changing_mac_output: str = subprocess.check_output(f"reg add {interface} /v NetworkAddress /d {new_mac_address} /f").decode()
				# print the command output
				print(changing_mac_output)
				break

		return adapter_index  # noqa

	def disable_adapter(adapter_index: int) -> str:
		# use wmic command to disable our adapter so the MAC address change is reflected
		return subprocess.check_output(f"wmic path win32_networkadapter where index={adapter_index} call disable").decode()

	def enable_adapter(adapter_index: int) -> str:
		# use wmic command to enable our adapter so the MAC address change is reflected
		return subprocess.check_output(f"wmic path win32_networkadapter where index={adapter_index} call enable").decode()

	if input('do you want to randomize (r) mac or change it to specific value?').lower() == 'r':
		new_mac_address: str = generate_random_mac()
	else:
		new_mac_address: str = input('enter new mac: ')

	connected_adapters_mac: list[tuple] = get_connected_adapters_mac_address()
	old_mac_address, target_transport_name = get_user_adapter_choice(connected_adapters_mac)

	print("[*] Old MAC address:", old_mac_address)
	
	adapter_index: int = change_mac_address(target_transport_name, new_mac_address)
	print("[+] Changed to:", new_mac_address)
	
	disable_adapter(adapter_index)
	print("[+] Adapter is disabled")
	
	enable_adapter(adapter_index)
	print("[+] Adapter is enabled again")
	t1 = time()
	print(f"[*] Done in {t1 - t0:.2f} seconds")


def _init_ports_info() -> tuple[list[int], list[str]]:
	with open("./hacking/data/ports_info.dat", 'rt', encoding='windows-1251') as f:
		ports_info: list[list] = eval(f.read())

	ports: list[int] = [i[0] for i in ports_info]
	info: list[str] = [i[1] for i in ports_info]
	return ports, info


def print_port_info(port: int) -> None:
	if port not in range(0, 65537):
		print(f'{RED}Not a port!')
		return
	
	ports, info = _init_ports_info()
	
	indexes: list[int] = [i for i, x in enumerate(ports) if x == port]

	print(f'Information about port {GREEN}{port}:')

	if not indexes:
		print(f'{RED}No information!')
		return
	
	for i in indexes:
		print('-', info[i])


def port_scan(host: str) -> set[int]:
	t0: float = time()

	q: Queue[int] = Queue()
	print_lock: Lock = Lock()

	ports, info = _init_ports_info()
	opened: set[int] = set()
	banners: dict[int, str] = {}

	def scan_port(port_: int):
		s: socket = socket.socket()
		try:
			s.connect((host, port_))
		except socket.error:
			pass
		else:
			opened.add(port_)
			try:
				pass
				# banners[port_] = s.recv(1024).decode()
			except socket.error:
				banners[port_] = 'no banner'
		finally:
			print(f'\rfound {len(opened)} opened ports', end='', flush=True)
			s.close()

	def scan_thread():
		while True:
			worker = q.get()  # noqa
			scan_port(worker)
			q.task_done()

	for _ in tqdm(range(N_THREADS), desc='Threads'):
		Thread(target=scan_thread, daemon=True).start()

	for worker in tqdm(ports, desc='Ports'):
		q.put(worker)

	q.join()

	t1: float = time()
	
	for port in sorted(opened):
		with print_lock:
			indexes: list[int] = [i for i, x in enumerate(ports) if x == port]
			
			message = f"{GREEN}{host:15}:{port:5} is opened -"
			print('\r', message, end=' ', sep='')
			
			if not indexes:
				print(f'{RED}no information!')
				continue
			
			print(f"{info[indexes[0]]}")
			
			for index in indexes[1:]:
				print(' ' * len(message), '- ', info[index], sep='')

			print(YELLOW + banners.get(port, 'no banner'))

	print(f'finished (found {len(opened)} opened ports)')

	print(f'{round(t1 - t0, 4)} s')
	
	return opened


def saved_wifi_passwords() -> None:
	def get_saved_ssids() -> list[str]:
		"""Returns a list of saved SSIDs in a Windows machine using netsh command"""
		output: str = subprocess.check_output("netsh wlan show profiles").decode()  # get all saved profiles in the PC
		ssids: list[str] = []
		profiles: list[str] = re.findall(r"All User Profile\s(.*)", output)
		for profile in profiles:
			ssid = profile.strip().strip(":").strip()  # for each SSID, remove spaces and colon
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
			ciphers: list[str] = re.findall(r"Cipher\s(.*)", ssid_details)
			ciphers: str = "/".join([c.strip().strip(":").strip() for c in ciphers])  # clear spaces and colon
			key: list[str] = re.findall(r"Key Content\s(.*)", ssid_details)  # get the Wi-Fi password
			try:
				key_s: str = key[0].strip().strip(':').strip()  # clear spaces and colon
			except IndexError:
				key_s: str = 'None'

			profile = Profile(ssid=ssid, ciphers=ciphers, key=key_s)

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

"""
def decrypt_password(password: bytes | bytearray, encryption_key: bytes | bytearray) -> str:
	try:
		iv: bytes | bytearray = password[3:15]
		password: bytes | bytearray = password[15:]
		cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
		return cipher.decrypt(password)[:-16].decode()
	except UnicodeDecodeError:
		try:
			return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
		except Exception:
			# not supported
			return ''


def saved_chrome_passwords() -> None:
	def get_chrome_datetime(chromedate: int) -> datetime:
		\"""Return a `datetime.datetime` object from a chrome format datetime
		Since `chromedate` is formatted as the number of microseconds since January 1601\"""
		return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

	def get_encryption_key() -> bytes | bytearray:
		local_state_path: PATH = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
		with open(local_state_path, "r", encoding="utf-8") as f:
			local_state = f.read()
			local_state = json.loads(local_state)

		# decode the encryption key from Base64
		key: bytes = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
		# remove DPAPI str
		key = key[5:]
		# return decrypted key that was originally encrypted
		# using a session key derived from current user's logon credentials
		# doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
		return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

	key: bytes | bytearray = get_encryption_key()
	# local sqlite Chrome database path
	db_path: PATH = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
	# copy the file to another location
	# as the database will be locked if chrome is currently running
	filename: PATH = "./ChromeData.db"
	shutil.copyfile(db_path, filename)
	db: Connection = connect(filename)
	cursor: Cursor = db.cursor()
	cursor.execute("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created")

	for row in cursor.fetchall():
		origin_url, action_url, username, _, date_created, date_last_used = row
		password: str = decrypt_password(row[3], key)

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

"""


def extract_emails(url: URL = "https://www.randomlists.com/email-addresses") -> tuple[str]:
	session: HTMLSession = HTMLSession()
	response: Response = session.get(url)
	render(response)  # noqa

	ans: tuple = tuple(re_match.group() for re_match in re.finditer(EMAIL_REGEX, response.html.raw_html.decode()))  # noqa
	return ans


def extract_links(url: URL = "https://www.randomlists.com/email-addresses", max_urls: int = 30) -> tuple[set[str], set[str]]:
	internal_urls: set[URL] = set()
	external_urls: set[URL] = set()

	max_urls -= 1

	total_urls_visited: int = 0

	def is_valid(url: URL) -> bool:
		"""Checks whether `url` is a valid URL."""
		parsed: ParseResult = urlparse(url)
		return bool(parsed.netloc and parsed.scheme)

	def get_all_website_links(url: URL) -> set[URL]:
		"""Returns all URLs that is found on `url` in which it belongs to the same website"""

		urls: set = set()
		domain_name: str = urlparse(url).netloc
		session: HTMLSession = HTMLSession()
		response: Response = session.get(url)

		render(response)  # noqa

		soup: BeautifulSoup = BeautifulSoup(response.html.html, 'html.parser')  # noqa
		for a_tag in soup.findAll('a'):
			href = a_tag.attrs.get('href')
			if not href:
				continue

			href = urljoin(url, href)
			parsed_href = urlparse(href)
			href = parsed_href.scheme + '://' + parsed_href.netloc + parsed_href.path  # remove URL GET parameters, URL fragments, etc.

			if not is_valid(href):
				continue
			if href in internal_urls:
				continue
			if domain_name not in href:  # is external link
				if href not in external_urls:
					print(f"{GRAY}[!] External link: {href}")
					external_urls.add(href)
				continue
			print(f"{GREEN}[*] Internal link: {href}")
			urls.add(href)
			internal_urls.add(href)
		return urls

	def crawl(url: URL, max_urls: int):
		"""
		Crawls a web page and extracts all links.
		You'll find all links in `external_urls` and `internal_urls` global set variables.
		"""
		global total_urls_visited
		total_urls_visited += 1
		print(f"{YELLOW}[*] Crawling: {url}")
		links: set[URL] = get_all_website_links(url)
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
