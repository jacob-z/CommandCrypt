#!/usr/bin/env python

"""Author: Jacob Zimmer

*** Free to use with attribution. ***

CommandCrypt may be used to encrypt and decrypt files using AES 128 encryption 
right from the command line. Specify single files or whole directories.  
You can also give a directory where the processed files will be stored.

Example:
	The default options for CommandCrypt are to encrypt the files specified in
	the immediate command line arguments.  If a directory is provided, only the
	files in the first level of the directory will be encrypted.  The resulting
	files will be stored in the current directory:

		$ python CommandCrypt.py samplefile.txt

	Command line arguments enable more complex operations and decryption.
	Use "-d" or "--decrypt" to decrypt an encrypted file.

		$ python CommandCrypt.py -d ENCsamplefile.txt

	Use "-r" or "--recurse" to include files in subdirectories.

		S python CommandCrypt.py -r ./sampleDir

	A directory for output can be speficied with the "--dest" flag.

		$ python CommandCrypt.py samplefile.txt --dest ./resultDir

Attributes:
	SALT_BYTES (int): The number of bytes to be used when salting passwords.
	ITERATIONS (int): The number of times to apply the hash function to itself.

Todo:
	* Add padding to smaller files
	* Store encrypted files in the specified destination
	* Maintain or encode file hierarchy in encrypted files

"""

import argparse, sys, os, base64, hashlib, timeit
from tendo import singleton
from Crypto.Cipher import AES
from Crypto import Random

SALT_BYTES = 32			# Number of bytes to salt the password with
ITERATIONS = 100000 	# Number of times to apply the hash function


def _addCLArguments():
	parser = argparse.ArgumentParser(description='CommandCrypt lets you encrypt'
		+ ' or decrypt files right from the command line. Specify single files'
		+ ' or whole directories to encrypt.  You can also give a directory'
		+ ' where the processed files will be stored.')

	parser.add_argument('files', metavar='files', type=str, nargs='+',
						help='files to be encrypted (default) or decrypted')
	parser.add_argument('--dest', metavar='directory', type=str, nargs=1,
						default=os.path.dirname(os.path.realpath(__file__)),
						help='folder to store processed files',dest='directory')
	parser.add_argument('-r', '--recurse', dest='recurse', action='store_true', 
						help='include files in subdirectories')
	meg = parser.add_mutually_exclusive_group()
	meg.add_argument('-e', '--encrypt', dest='operation', action='store_const', 
					 const=encrypt, default=encrypt, help='encrypt files')
	meg.add_argument('-d', '--decrypt', dest='operation', action='store_const', 
					 const=decrypt, default=encrypt, help='decrypt files')

	args = parser.parse_args()

	return {'operation': args.operation, 'recurse': args.recurse,
			'files': args.files, 'directory': args.directory}


def _generatePassword(passphrase, salt = 0):
	salt = Random.new().read(SALT_BYTES)
	password = hashlib.pbkdf2_hmac('sha256', passphrase, salt, ITERATIONS)
	return (password, salt)


def testPBKFD2():
	"""Run timing tests on the password generating function."""
	print "Starting timing tests: "
	times = {}
	for pwdSize in range(1,51, 10):
		pwd = ''.join(['%c' % x for x in range(65, 65+pwdSize)])
		times[pwd] = 0
		print "Password: (" + str(pwdSize) + ") " + pwd
		for count in range(1,10):
			t0 = timeit.default_timer()
			_generatePassword(pwd)
			t1 = timeit.default_timer()
			times[pwd] += t1 - t0
		times[pwd] = times[pwd]/10
		print "Average time: " + str(times[pwd])


def readPlaintextFile(filename):
	"""Open unencrypted files.

	Args:
		filename (str): The file to be read.

	Returns:
		str: The contents of filename.
	"""
	with open(filename, 'r') as f:
		return f.read()


def writePlaintextFile(filename, p):
	"""Write decrypted contents to file.

	Args:
		filename (str): The file to be read.
		p (str): The contents to be written to file.
	"""
	parts = filename.split("/")
	filename = "/".join(parts[:-1]) + "/DEC" + parts[-1]
	with open(filename, 'w') as f:
		f.write(p)


def readCyphertextFile(filename):
	"""Open encrypted files, remove encoding and recover salt, iv and cyphertext.
	
	Args:
		filename (str): The file to be read.

	Returns:
		(str, str, str): The salt, iv, and cyphertext of filename
	"""
	with open(filename, 'r') as f:
		c = f.read()
		c = base64.b64decode(c)
		salt = c[:SALT_BYTES]
		iv = c[SALT_BYTES : (SALT_BYTES+AES.block_size)]
		c = c[(SALT_BYTES+AES.block_size) : ]
		return (salt, iv, c)


def writeCyphertextFile(filename, c):
	"""Write encrypted contents to file.

	Args:
		filename (str): The file to be read.
		c (str): The contents to be written to file.
	"""
	parts = filename.split("/")
	filename = "/".join(parts[:-1]) + "/ENC" + parts[-1]	
	with open(filename, 'w') as f:
		f.write(c)


def encrypt(filename, passphrase):
	"""Encrypt the contents of filename with AES128 and writes the file to disk.

	Args:
		filename (str): The file to be encrypted.
		passphrase (str): A phrase to be used to generate a more secure password.
	"""
	p = readPlaintextFile(filename)
	password, salt = _generatePassword(passphrase)
	iv = Random.new().read(AES.block_size)
 	aes = AES.new(password, AES.MODE_CFB, iv)
 	c = base64.b64encode(salt + iv + aes.encrypt(p))
 	writeCyphertextFile(filename, c)


def decrypt(filename, passphrase):
	"""Decrypt the contents of filename with AES128 and writes the file to disk.

	Args:
		filename (str): The file to be decrypted.
		passphrase (str): A phrase to be used to generate a more secure password.
	"""
	salt, iv, c = readCyphertextFile(filename)
	password, tmp = _generatePassword(passphrase, salt) 
	if (tmp != salt):
		sys.stdout.write("CommandCrypt: decrypt: Error processing file.")
		sys.exit(1)
	aes = AES.new(password, AES.MODE_CFB, iv)
 	p = aes.decrypt(c)
 	writePlaintextFile(filename, p)


def main(argv):
	"""Process command line arguments and encrypt or decrypt files.

	Args:
		argv (list): The command line arguments to process.
	"""

	args = _addCLArguments()

	op      = args['operation']
	files   = list(args['files'])
	recurse = args['recurse']
	dest    = os.path.abspath("".join(args['directory']))

	if (op == encrypt) and recurse:
		sys.stdout.write("Recursively encrypting " + ", ".join(files))
	elif (op == decrypt) and recurse:
		sys.stdout.write("Recursively decrypting " + ", ".join(files))
	elif (op == encrypt) and not recurse:
		sys.stdout.write("Encrypting " + ", ".join(files))
	elif (op == decrypt) and not recurse:
		sys.stdout.write("Decrypting " + ", ".join(files))

	sys.stdout.write("\nThe result will be stored in " + dest + "\n")

	passphrase = raw_input("Enter password to continue: ")

	for file in files:
		path = os.path.abspath(file)

		if (os.path.isdir(path)):
			if ((file in args['files']) or recurse):
				for f in os.listdir(path):
					files.append(path + "/" + f)
		elif (os.path.isfile(path)):
			print "Processing: " + path
			op(path, passphrase)
		else:
			sys.stderr.write("CommandCrypt: Error processing files\n")
			sys.exit(1)

	sys.stdout.write("Your files have been processed.\n")


if __name__ == "__main__":
	# Only runs if this module is run directly.

	# Prevent multiple instances running from same directory
	me = singleton.SingleInstance()
	main(sys.argv)
