import csv
import multiprocessing
import string
import time

from argon2 import PasswordHasher
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from itertools import product
from typing import Optional


DEFAULT_UNAME = 'user-01'
MAX_PASSWD_LENGTH = 5
MIN_PASSWD_LENGTH = 5
PASSWD_FILE_NAME = 'passwd.csv'
PERMITTED_ALPHABET = string.digits



ph = PasswordHasher(
	time_cost = 3,          # Number of iterations
	memory_cost = 65536,    # Memory usage in kibibytes (64MiB)
	parallelism = 1,        # Number of parallel threads
	hash_len = 32,          # Length of resulting hash
	salt_len = 16           # Length of random salt
)


def get_target_hash(uname: str, passwd_file_path: str = PASSWD_FILE_NAME, encoding: str = 'utf-8', uname_col: int = 0, hash_col: int = 2) -> Optional[str]:
	"""
		Retrieve the password hash matching the username provided from the password file whose path is given.
		Returns the corresponding password hash or None if not found
	"""


	with open(file=passwd_file_path, mode='r', newline='', encoding=encoding) as passwd_file:
		reader = csv.reader(passwd_file)
		
		for row in reader:
			if len(row) <= max(uname_col, hash_col): continue
			if row[uname_col].strip() == uname: return row[hash_col].strip()
	
	return None



def generate_guesses(alphabet: str = PERMITTED_ALPHABET, min_length: int = MIN_PASSWD_LENGTH, max_length: int = MAX_PASSWD_LENGTH):
	"""
		A generator that yields all possible guesses from min_length upto max_length.
		This is memory efficient as it doesn't create a massive list.
	"""

	for length in range(min_length, max_length + 1):
		for t in product(alphabet, repeat=length):
			yield ''.join(t)



def check_password(guess: str, target_hash: str) -> str | None:
	"""
		Verifies one guess against the target hash.
		Returns the guess if it matches, else None.
	"""

	try:
		if ph.verify(hash=target_hash, password=guess):
			return guess
	except Exception: pass

	return None



def main() -> tuple[str, str] | None:
	"""
		Set up and run parallel password search.
		Returns (correct password, time taken to find) or None if password is not found.
	"""

	uname = input('Enter the USERNAME to crack (e.g., user-01): ').strip()
	if not uname: uname = DEFAULT_UNAME

	target_hash = get_target_hash(uname=uname)
	if not target_hash: exit('No hash matching username, or invalid username')

	min_length = input('Enter the MINIMUM POSSIBLE PASSWORD LENGTH: ').strip()
	if not min_length or not min_length.isdigit(): min_length = MIN_PASSWD_LENGTH

	max_length = input('Enter the MAXIMUM POSSIBLE PASSWORD LENGTH: ').strip()
	if not max_length or not max_length.isdigit(): max_length = MAX_PASSWD_LENGTH

	# Create the generator to produce the tasks
	guesses_generator = generate_guesses(min_length=int(min_length), max_length=int(max_length))

	# Bake in the `target_hash` argument into `check_password` function using `functools.partial`
	# (since `check_password` takes two args but `executor.map` only sends one)
	check_with_target_hash = partial(check_password, target_hash=target_hash)

	password_found = None
	start_time = time.time()

	# Determine number of workers to use
	num_workers = multiprocessing.cpu_count()

	# Use `ProcessPoolExecutor` to manage a pool of worker processes
	with ProcessPoolExecutor(max_workers=num_workers) as executor:
		# `executor.map` applies the partial function `check_with_target_hash` to
		# every item in `guesses_generator` in parallel

		# `chunksize` is a performance tuning to send multiple guesses to a worker at once
		# reducing inter-process communication overhead 

		results = executor.map(check_with_target_hash, guesses_generator, chunksize=1)

		# Iterate over results as they are completed
		for result in results:
			if result:
				password_found = result
				executor.shutdown(wait=False, cancel_futures=True)		# Stop the search once correct password is found
				break
	
	end_time = time.time()

	if password_found: return password_found, f'{end_time - start_time:.4f}'
	return None



if __name__ == '__main__':
	print(main())
