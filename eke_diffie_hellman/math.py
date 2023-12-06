from Crypto.Util.number import getPrime
import random
import math

def findPrimefactors(n) :
	s = {}
	# Print the number of 2s that divide n 
	while (n % 2 == 0) :
		if 2 not in s:
			s[2] = 1
		else:
			s[2] += 1
		n = n // 2

	# n must be odd at this point. So we can 
	# skip one element (Note i = i +2) 
	for i in range(3, int(math.sqrt(n)), 2):
		# While i divides n, print i and divide n 
		while (n % i == 0) :
			if i not in s:
				s[i] = 1
			else:
				s[i] += 1
			n = n // i 
		
	# This condition is to handle the case 
	# when n is a prime number greater than 2 
	if (n > 2) :
		s[n] = 1
	
	return s

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

def get_primitive_root(n):
    '''
    Argument:
        n: a 1024 bit prime number. All prime numbers have primitive roots. Hence, we know it has a primitive root
    Returns:
        g : the primitive root of n
    '''

    # euler's totient function
    # for a prime number p, euler's totient is p-1
    phi = n-1

    # Generate a list of possible multiplicative orders
    # We know that multiplicative orders will divide phi. Hence, get the factors of phi
    s = findPrimefactors(phi)
    print(s)
    s = s.keys()
    # Generate numbers coprime to n. This can be any number from 2 to n-1 since n is prime
    # a = a number coprime to n
    # This is a possible primitive root
 
    found = False
    while True:
        a = random.randint(2,n-1)
        print("A", a)
		#Algorithm 4.80: Finding a generator of cyclic group from Applied Cryptography by A.J. Menezes et al.
        for it in s:
            print(it, power(a, phi // it, n))
            if (power(a, phi // it, n) == 1):
                found = True
                break
        if found ==False:
            return a
			
    # for k in list of multiplicative orders
    # Check if a^k mod n == 1. If it is, then a is not a primitive root. Start again
    # Else, a is a primitive root since k=phi. Return this


n = getPrime(256)
print(n)
print(get_primitive_root(n))