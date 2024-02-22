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

# This also works
# def gcdExtended(a, b):
 
#     # Base Case
#     if a == 0:
#         return b, 0, 1
 
#     gcd, x1, y1 = gcdExtended(b % a, a)
 
#     # Update x and y using results of recursive
#     # call
#     x = y1 - (b//a) * x1
#     y = x1
 
#     return gcd, x, y

# montgomery product
def mon_product(A,B,n,N,r):
    t = (A * B) % r
    m = (t * N) % r
    # U = ((A * B) + (m * n)) // r 
    U = (t + m * n) // r
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

def mon_mod_exp(base, exp, n, r):
    gcd, x,y = egcd(r,n)
    if gcd != 1:
        return False
    # n_inv = -y
    n_inv = y
    M = (base*r) % n
    X = r % n
    length = len(bin(exp))-3
    for i in range(length,-1,-1):
        X = mon_product(X,X, n, n_inv,r)
        if (exp >> i) & 1:
            X = mon_product(M,X, n, n_inv,r)
    x = mon_product(X,1, n, n_inv,r)
    return x

# print(mon_mod_exp(3,4,7,2))
###############################################
#chatgpt version

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm
    Returns (gcd, x, y) where gcd is the greatest common divisor of a and b,
    and x, y are coefficients such that gcd = ax + by.
    """
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return (gcd, y - (b // a) * x, x)

def montgomery_reduction(t, n, n_inv, r):
    """
    Montgomery reduction
    Returns t * r^(-1) mod n.
    """
    m = (t * n_inv) % r
    u = (t + m * n) // r
    return u if u < n else u - n

def MonPro(a, b, n, n_inv, r):
    """
    Montgomery multiplication
    Returns a * b * r^(-1) mod n.
    """
    t = (a * b) % r
    return montgomery_reduction(t, n, n_inv, r)

def ModExp(a, e, n):
    """
    Modular exponentiation using Montgomery multiplication
    Returns a^e mod n.
    """
    # Step 1: Compute n using the extended Euclidean algorithm
    _, _, n_inv = extended_gcd(n, 1)
    
    # Step 2: Compute a * r mod n
    a = (a * r) % n

    # Step 3: Initialize x = 1 * r mod n
    x = r % n

    # Step 4: Loop over each bit of the exponent e
    for i in range(len(bin(e)) - 2, -1, -1):
        # Step 5: Square x
        x = MonPro(x, x, n, n_inv, r)
        
        # Step 6: If the ith bit of e is 1, multiply x by a
        if (e >> i) & 1:
            x = MonPro(a, x, n, n_inv, r)

    # Step 7: Final Montgomery multiplication
    x = MonPro(1, x, n, n_inv, r)

    return x

# Example usage:
a = 5
e = 17
n = 13
# r = 2 ** (len(bin(n)) - 2) # r = 2^(number of bits in n)
r = 1
while r < n:
    r <<= 1
result = ModExp(a, e, n)
print("Result:", result)
print(montgomery_modular_exponentiation(a,e,n))
print(power(a,e,n))
print(mon_mod_exp(a,e,n,r))