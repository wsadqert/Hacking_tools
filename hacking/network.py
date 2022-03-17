import socket
import regex as re
import string
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import subprocess
from threading import Thread, Lock
import os
import random
from colorama import init, Fore
from queue import Queue
from collections import namedtuple
import shutil
from datetime import datetime, timedelta


def get_random_mac() -> str:
	"""Generate and return a MAC address in the format of WINDOWS"""
	# get the hexdigits uppercased
	uppercased_hexdigits = ''.join(set(string.hexdigits.upper()))
	# 2nd character must be 2, 4, A, or E
	return random.choice(uppercased_hexdigits) + random.choice("24AE") + "".join(
		random.sample(uppercased_hexdigits, k=10))


def random_mac_address():
	network_interface_reg_path = r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
	transport_name_regex = re.compile("{.+}")
	mac_address_regex = re.compile(r"([A-Z0-9]{2}[:-]){5}([A-Z0-9]{2})")

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
			mac_address = mac_address_regex.search(potential_mac)
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
		output = subprocess.check_output(f"reg QUERY " + network_interface_reg_path.replace("\\\\", "\\")).decode()
		for interface in re.findall(rf"{network_interface_reg_path}\\\d+", output):
			# get the adapter index
			adapter_index = int(interface.split("\\")[-1])
			interface_content = subprocess.check_output(f"reg QUERY {interface.strip()}").decode()

			if adapter_transport_name in interface_content:
				# if the transport name of the adapter is found on the output of the reg QUERY command
				# then this is the adapter we're looking for
				# change the MAC address using reg ADD command
				changing_mac_output = subprocess.check_output(
					f"reg add {interface} /v NetworkAddress /d {new_mac_address} /f").decode()
				# print the command output
				print(changing_mac_output)
				# break out of the loop as we're done
				break

		return adapter_index

	def disable_adapter(adapter_index: int) -> str:
		# use wmic command to disable our adapter so the MAC address change is reflected
		disable_output = subprocess.check_output(
			f"wmic path win32_networkadapter where index={adapter_index} call disable").decode()
		return disable_output

	def enable_adapter(adapter_index: int) -> str:
		# use wmic command to enable our adapter so the MAC address change is reflected
		enable_output = subprocess.check_output(
			f"wmic path win32_networkadapter where index={adapter_index} call enable").decode()
		return enable_output

	if input('do you want to randomize mac? '):
		# if random parameter is set, generate a random MAC
		new_mac_address = get_random_mac()
	connected_adapters_mac = get_connected_adapters_mac_address()
	old_mac_address, target_transport_name = get_user_adapter_choice(connected_adapters_mac)

	print("[*] Old MAC address:", old_mac_address)
	adapter_index = change_mac_address(target_transport_name, new_mac_address)
	print("[+] Changed to:", new_mac_address)
	disable_adapter(adapter_index)
	print("[+] Adapter is disabled")
	enable_adapter(adapter_index)
	print("[+] Adapter is enabled again")


def port_scan():
	init()
	GREEN: str = Fore.GREEN
	RESET: str = Fore.RESET
	GRAY: str = Fore.LIGHTBLACK_EX

	N_THREADS: int = 1000
	q: Queue = Queue()
	print_lock: Lock = Lock()

	# parse_wiki()

	with open("D:/ports_info.txt", 'rt', encoding='windows-1251') as f:
		ports_info = eval(f.read())

	ports = [i[0] for i in ports_info]
	info = [i[1] for i in ports_info]

	ports_info = dict(zip(ports, info))

	opened: set[int] = set()

	def scan_port(port):
		s = socket.socket()
		try:
			s.connect((host, port))
		except socket.error:
			with print_lock:
				print(f"\r{GRAY}{host:15}:{port:5} is closed {RESET}", end='', flush=True)
		else:
			with print_lock:
				print(f"\r{GREEN}{host:15}:{port:5} is opened {RESET}- {ports_info[port]}")
				opened.add(port)
		finally:
			s.close()

	def scan_thread():
		while True:
			worker = q.get()
			scan_port(worker)
			q.task_done()

	def main(host, ports):
		for t in range(N_THREADS):
			t = Thread(target=scan_thread)
			t.daemon = True
			t.start()

		for worker in ports:
			q.put(worker)

		q.join()

	host = input('host: ')
	main(host, ports)
	print(f'\rfinished {tuple(sorted(opened))}', end='', flush=True)


def saved_wifi_passwords() -> None:
	Profile = namedtuple("Profile", ["ssid", "ciphers", "key"])

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
			ciphers: str = re.findall(r"Cipher\s(.*)", ssid_details)
			# clear spaces and colon
			ciphers: str = "/".join([c.strip().strip(":").strip() for c in ciphers])
			# get the Wi-Fi __password
			key: str = re.findall(r"Key Content\s(.*)", ssid_details)
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

	def get_chrome_datetime(chromedate):
		"""Return a `datetime.datetime` object from a chrome format datetime
		Since `chromedate` is formatted as the number of microseconds since January, 1601"""
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

	def decrypt_password(password, key):
		try:
			# get the initialization vector
			iv = password[3:15]
			password = password[15:]
			# generate cipher
			cipher = AES.new(key, AES.MODE_GCM, iv)
			# decrypt __password
			return cipher.decrypt(password)[:-16].decode()
		except:
			try:
				return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
			except:
				# not supported
				return ""

	# get the AES key
	key = get_encryption_key()
	# local sqlite Chrome database path
	db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
	# copy the file to another location
	# as the database will be locked if chrome is currently running
	filename = "ChromeData.db"
	shutil.copyfile(db_path, filename)
	# connect to the database
	db = sqlite3.connect(filename)
	cursor = db.cursor()
	# `logins` table has the data we need
	cursor.execute(
		"select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
	# iterate over all rows
	for row in cursor.fetchall():
		origin_url = row[0]
		action_url = row[1]
		username = row[2]
		password = decrypt_password(row[3], key)
		date_created = row[4]
		date_last_used = row[5]
		if username or password:
			print(f"Origin URL: {origin_url}")
			print(f"Action URL: {action_url}")
			print(f"Username: {username}")
			print(f"Password: {password}")
		else:
			continue
		if date_created != 86400000000 and date_created:
			print(f"Creation date: {str(get_chrome_datetime(date_created))}")
		if date_last_used != 86400000000 and date_last_used:
			print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
		print("=" * 50)

	cursor.close()
	db.close()
	try:
		# try to remove the copied db file
		os.remove(filename)
	except:
		pass

	return

