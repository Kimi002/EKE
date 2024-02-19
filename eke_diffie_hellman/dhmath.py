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

def montgomery_modular_exponentiation(base, exponent, modulus):
    result = 1
    base = (base % modulus + modulus) % modulus
    exponent = exponent % (modulus - 1)

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus

    return result

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
        x = montgomery_modular_exponentiation(a, d, n)
        if x == 1 or x == n - 1:
			# This is the case when we can not determine if the number is prime or not
            continue
        for _ in range(r - 1):
            x = montgomery_modular_exponentiation(x, 2, n)
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


# Extended Euclidean Algorithm
# can find x and y such that ax+by = gcd(a,b)
# Used by montgomery modular exponentiation
def egcd(a, b):
	# x and y are s_old and t_old
	# u and v are si and ti
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

# montgomery product
def mon_product(A,B,n,N,r):
    t = (A * B) % r
    m = (t * N) % r
    U = ((A * B) + (m * n)) // r
    if U>=n:
        return U-n
    else:
        return U

# modular multiplication
# we want a.b (mod n)
# a,b,n are k-bits long
# def mon_mod_mult(a,b,n,n_prime,r):
#     A = (a * r) % n
#     u = mon_product(A,b, n, n_prime, r)
#     print("u", u)
#     return u

def mon_mod_exp(base, exp, n,k):
    # k is the number of bits
    r = 2**k
    gcd, x,y = egcd(r,n)
    n_prime = -y
    r_prime = x
    print(n, n_prime, r, r_prime)
    M = (base*r) % n
    X = r % n
    print(M,X)
    # for i in range(k-1,0,-1):
    while exp>0:
        print(x)
        x = mon_product(X,X, n, n_prime,r)
        if exp%2 == 1:
            print(X)
            X = mon_product(M,X, n, n_prime,r)
        exp = exp//2
    print(x)
    x = mon_product(X,1, n, n_prime,r)
    return x

print(mon_mod_exp(3,4,7,2))