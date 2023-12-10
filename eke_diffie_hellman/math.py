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


# n = getPrime(256)
# print(n)
# print(get_primitive_root(n))
#-------------------------------------------------------------------------------------------------


def miller_rabin_test(n, k=5):
    """
    Miller-Rabin primality test.
    
    Parameters:
    - n: The number to be tested for primality.
    - k: The number of iterations (witness tests). Higher values increase accuracy.

    Returns:
    - True if n is likely prime, False if n is composite.
    """
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = power(a, d, n)
        if x == 1 or x == n - 1:
			# This is the case when we can not determine if the number is prime or not
            continue
        for _ in range(r - 1):
            x = power(x, 2, n)
			# if x == 1:
			# 	return False
            if x == n - 1:
                break
        else:
            return False  # n is composite

    return True  # n is likely prime

def get_safe_prime(q):
	# if q is Sophie Germain Prime, return 2q+1 (safe prime)
	p = (2*q)+ 1
	if miller_rabin_test(p):
		return p
	else:
		print("not prime")
		return -1

def check_2_not_square_mod_p(p):
	if (p%8 == 3) or (p%8 == 5):
		return True
	return False


# way 1
# get safe prime
# check if p mod 8 = +-3 mod 8
# If this is true, then the order of g=2 is 2q which is phi
# Hence, 2 is a generator

# while True:
# 	q = getPrime(1024)
# 	p = get_safe_prime(q)
# 	if p != -1:
# 		okay = check_2_not_square_mod_p(p)
# 		if okay:
# 			break

# print("modulus =",p)

# Euler's totient p is 2*q
# Any number co prime to q (any number between 1 and q) is the generator for group 1 to q
# Take a random, or find the smallest x such that g^2 != 1 and  g^q = 1. Then we have a generator

while True:
	q = getPrime(1024)
	print(miller_rabin_test(q))
	p = get_safe_prime(q)
	print("got p")
	if p == -1:
		continue
	print("modulus =",p)

	while True:
		g = random.randint(2,p-1)
		# BigInteger exp = (p.subtract(BigInteger.ONE)).divide(q); = (p-1)/q = 2
		exp = 2
		if power(g,2,p) != 1:
			break
	print(power(g,q,p))
	break


print()
print(p)
print()
print(g)

# The above code is fast
# Problem : Cannot find safe prime. Loop keeps running because get_safe_prime returns -1
# q is prime but miller_rabin_test(2*q+1) returns false
