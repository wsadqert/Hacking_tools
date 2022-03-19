from cryptography.fernet import Fernet


def generate_key() -> bytes:
	return Fernet.generate_key()


def write_key(key_file: str, key: bytes) -> None:
	"""
	Saves key into a file
	"""
	with open(key_file, "wb") as key_file:
		key_file.write(key)


def load_key(key_file: str) -> bytes:
	"""
	Loads the key from the current directory named `key.key`
	"""
	return open(key_file, 'rb').read()


def encrypt(filename: str, key: bytes) -> None:
	"""
	Given a filename (str) and key (bytes), it encrypts the f and write it
	"""
	fernet = Fernet(key)

	with open(filename, 'rb') as f:
		data = f.read()

	encrypted = fernet.encrypt(data)

	with open(filename, 'wb') as f:
		f.write(encrypted)


def decrypt(filename: str, key: bytes) -> None:
	"""
	Given a filename (str) and key (bytes), it decrypts the f and write it
	"""
	fernet = Fernet(key)

	with open(filename, 'rb') as f:
		encrypted = f.read()

	decrypted = fernet.decrypt(encrypted)

	with open(filename, 'wb') as f:
		f.write(decrypted)

