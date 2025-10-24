import csv
import random
import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import HashingError


MAX_PASSWD_LENGTH = 4
MIN_PASSWD_LENGTH = 4
NUMBER_OF_USERS = 5
UNAME_PREFIX = 'user-'
PASSWD_FILE_NAME = 'passwd.csv'
PERMITTED_ALPHABET = string.digits



ph = PasswordHasher(
	time_cost = 3,          # Number of iterations
	memory_cost = 65536,    # Memory usage in kibibytes (64MiB)
	parallelism = 1,        # Number of parallel threads
	hash_len = 32,          # Length of resulting hash
	salt_len = 16           # Length of random salt
)



number_of_users = NUMBER_OF_USERS
min_passwd_length = MIN_PASSWD_LENGTH
max_passwd_length = MAX_PASSWD_LENGTH


try: number_of_users = int(input(f'Enter the NUMBER OF USERS:  '))
except Exception as e: print(f'{e} \n USING DEFAULT VALUE {NUMBER_OF_USERS}')

try: min_passwd_length = int(input(f'Enter the MINIMUM PASSWORD LENGTH:  '))
except Exception as e: print(f'{e} \n USING DEFAULT VALUE {MAX_PASSWD_LENGTH}')

try: max_passwd_length = int(input(f'Enter the MAXIMUM PASSWORD LENGTH:  '))
except Exception as e: print(f'{e} \n USING DEFAULT VALUE {MIN_PASSWD_LENGTH}')



with open(file=PASSWD_FILE_NAME, newline='', mode='w', encoding='utf-8') as passwd_file:
	writer = csv.writer(passwd_file)

	for i in range(number_of_users):
		username = f'{UNAME_PREFIX}{i+1:02}'
		passwd = ''.join(secrets.choice(PERMITTED_ALPHABET) for i in range(random.randint(min_passwd_length, max_passwd_length)))
		hashed_passwd = None

		try: hashed_passwd = ph.hash(password=passwd)
		except HashingError as hashing_err: print(hashing_err)
		except Exception as e: print(e)

		writer.writerow([username, passwd, hashed_passwd])
