import random
from base64 import b64encode

def b64e(x):
    return b64encode(x).decode('utf-8')

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






#---------------------------------------------------------
# Euler's totient p is 2*q
# Any number co prime to q (any number between 1 and q) is the generator for group 1 to q
# Take a random, or find the smallest x such that g^2 != 1 and  g^q = 1. Then we have a generator
# Below was my implementation to get DH parameters
# Almost correct

#----------------------------------------------
###
# Corrected version
# generator is a quadratic non residue
# Quadratic non residue has legendre value = -1
# Legendre value = a**((p-1)/2) = a**q

# moved func to eke