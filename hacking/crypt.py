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


'''
parser = argparse.ArgumentParser(description="Simple File Encryptor Script")
parser.add_argument("file", help="File to encrypt/decrypt")
parser.add_argument("-g", "--generate-key", dest="generate_key", action="store_true", help="Whether to generate a new key or use existing")
parser.add_argument("-e", "--encrypt", action="store_true", help="Whether to encrypt the file, only -e or -d can be specified.")
parser.add_argument("-d", "--decrypt", action="store_true", help="Whether to decrypt the file, only -e or -d can be specified.")

args = parser.parse_args()
file = args.file
generate_key = args.generate_key

if generate_key:
	write_key()
key = load_key()

encrypt_ = args.encrypt
decrypt_ = args.decrypt

if encrypt_ and decrypt_:
	raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")
elif encrypt_:
	encrypt(file, key)
elif decrypt_:
	decrypt(file, key)
else:
	raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")

'''
