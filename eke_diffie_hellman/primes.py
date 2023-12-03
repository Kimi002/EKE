from random import randint
from base64 import b64encode
from sympy import primitive_root
from Crypto.Util.number import getPrime

# Generate a prime number
def gen_prime(start, stop):
    mod_list = []

    # Generate a list of prime numbers
    for num in range(start, stop):
        if num > 1:
            for i in range(2, num):
                if (num%i) == 0:
                    break
            else:
                mod_list.append(num)

    x = randint(0, len(mod_list))
    return mod_list[x]

def b64e(x):
    return b64encode(x).decode('utf-8')


def find_random_primitive_root(n):
    smallest_primitive_root = primitive_root(n)
    # The function below generates a random primitive root modulo n
    random_primitive_root = pow(smallest_primitive_root, randint(1, n - 2), n)
    return random_primitive_root


# program to find primitive root 
# of a given number n 
#-------------------------------------------------------------------------------------------
from math import sqrt

# Returns True if n is prime 
def isPrime( n): 

	# Corner cases 
	if (n <= 1):
		return False
	if (n <= 3):
		return True

	# This is checked so that we can skip 
	# middle five numbers in below loop 
	if (n % 2 == 0 or n % 3 == 0):
		return False
	i = 5
	while(i * i <= n):
		if (n % i == 0 or n % (i + 2) == 0) :
			return False
		i = i + 6

	return True

""" Iterative Function to calculate (x^n)%p
	in O(logy) */"""
def power( x, y, p): 

	res = 1 # Initialize result 

	x = x % p # Update x if it is more 
			# than or equal to p 

	while (y > 0): 

		# If y is odd, multiply x with result 
		if (y & 1):
			res = (res * x) % p 

		# y must be even now 
		y = y >> 1 # y = y/2 
		x = (x * x) % p 

	return res 

# Utility function to store prime
# factors of a number 
def findPrimefactors(s, n) :

	# Print the number of 2s that divide n 
	while (n % 2 == 0) :
		s.add(2) 
		n = n // 2

	# n must be odd at this point. So we can 
	# skip one element (Note i = i +2) 
	for i in range(3, int(sqrt(n)), 2):
		
		# While i divides n, print i and divide n 
		while (n % i == 0) :

			s.add(i) 
			n = n // i 
		
	# This condition is to handle the case 
	# when n is a prime number greater than 2 
	if (n > 2) :
		s.add(n) 

# Function to find smallest primitive 
# root of n 
def findPrimitive( n) :
	s = set() 

	# Check if n is prime or not 
	if (isPrime(n) == False): 
		return -1

	# Find value of Euler Totient function 
	# of n. Since n is a prime number, the 
	# value of Euler Totient function is n-1 
	# as there are n-1 relatively prime numbers.
	phi = n - 1

	# Find prime factors of phi and store in a set 
	findPrimefactors(s, phi) 

	# Check for every number from 2 to phi 
	for r in range(2, phi + 1): 

		# Iterate through all prime factors of phi. 
		# and check if we found a power with value 1 
		flag = False
		for it in s: 

			# Check if r^((phi)/primefactors)
			# mod n is 1 or not 
			if (power(r, phi // it, n) == 1): 

				flag = True
				break
			
		# If there was no power with value 1. 
		if (flag == False):
			return r 

	# If no primitive root found 
	return -1

#--------------------------------------------------------------------------------------------

def get_parameters():
	k = getPrime(1024)
	# TODO: check if p is prime. If not, generate again
	p = (2*k) + 1

	not_found = True
	while not_found:
		x = randint(0,p-1)
		print(x)
		is_root = True
		for exponent in range(1,k+1):
			print("k")
			if power(x, exponent, p) == 1:
				print("break")
				is_root = False
				break
		if is_root:
			not_found = False
		# return(p,x)
	
	return(p,x)

print(get_parameters())

