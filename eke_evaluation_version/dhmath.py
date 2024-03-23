import random
from base64 import b64encode
import base64

def int_to_base64(num):
    # Convert integer to bytes
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
    # Encode bytes to base64
    base64_encoded = base64.b64encode(num_bytes)
    return base64_encoded.decode('utf-8')

def b64e(x):
    return b64encode(x).decode('utf-8')

# square and multiply method
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

# incorrect method - no longer used
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

# efficient primality test
def miller_rabin_test(n,exponentiation_term,k=5):
    """
    Miller-Rabin primality test.
    
    Parameters:
    - n: The number to be tested for primality.
    - k: The number of iterations (witness tests). Higher values increase accuracy.
    - exponentiation term: required only for montgomery exponentation. No relevance to miller rabin test

    Returns:
    - True if n is likely prime, False if n is composite.
    """

    # handle base cases
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Find r and odd number d such that n = 2^r * d + 1
    # s = s+1; r=r//2
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        # b in algo = random number
        # b^r mod a
        a = random.randint(2, n - 2)
        # x = montgomery_modular_exponentiation(a, d, n)
        x = mon_mod_exp(a,d,n,exponentiation_term)
        if x == 1 or x == n - 1:
			# This is the case when we can not determine if the number is prime or not (y = +/-1)
            continue

        # if y != +/- 1 then
            # while j < s-1 and y!=a'
        for _ in range(r - 1):
            # x = montgomery_modular_exponentiation(x, 2, n)
            # y = y^2 mod a
            x = mon_mod_exp(x,2,n,exponentiation_term)
            # If y=1, then return c=0 which means number is composite
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False  # n is composite
        # If loop ends and y!=a', then return False. Otherwise return True
        # if x != n - 1:
        #     return False

    return True  # n is likely prime

# Checks if input is Sophie Germain prime and returns the corresponding safe prime
def get_safe_prime(q):
	# if q is Sophie Germain Prime, return 2q+1 (safe prime)
    p = (2*q)+ 1
    r = 1
    while r < p:
        r <<= 1
    if miller_rabin_test(p, r):
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


def find_n_inv(n, r):
    """
    Find the modular multiplicative inverse of n modulo r satisfying r * r_inv - n * n_inv = 1.
    """
    gcd, x, y = extended_gcd(n,r)
    if gcd != 1:
        raise ValueError(f"The modular inverse does not exist for {a} modulo {m}.")
    
    return (-x)%r

# Another Extended Euclidean Algorithm
def gcdExtended(a, b):
 
    # Base Case
    if a == 0:
        return b, 0, 1
 
    gcd, x1, y1 = gcdExtended(b % a, a)
 
    # Update x and y using results of recursive
    # call
    x = y1 - (b//a) * x1
    y = x1
 
    return gcd, x, y

# Yet another Extended Euclidean Algorithm
def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm to find modular inverse.
    Returns (gcd, x, y) such that a*x + b*y = gcd.
    """
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return (gcd, y - (b // a) * x, x)

# montgomery product
def mon_product(a_bar,b_bar,n,n_inv,r):
    t = (a_bar * b_bar)
    # print("t:",t, end="  ;   ")
    m = (t * n_inv) % r
    # print("m:",m, end="  ;   ")
    U = (t + (m * n)) // r
    # print("U:",U, end="  ;   ")
    if U>=n:
        # print("U-n:",U-n, end="  ;   ")
        return U-n
    else:
        # print("U:",U, end="  ;   ")
        return U

# modular multiplication
# we want a.b (mod n)
# a,b,n are k-bits long
# def mon_mod_mult(a,b,n,n_prime,r):
#     A = (a * r) % n
#     u = mon_product(A,b, n, n_prime, r)
#     print("u", u)
#     return u

# Montgomery modular exponentiation - efficient
def mon_mod_exp(base, exp, n, r):
    gcd, x,y = egcd(r,n)
    if gcd != 1:
        return False
    n_inv = -y
    M = (base*r) % n
    X = r % n
    length = len(bin(exp))-3
    for i in range(length,-1,-1):
        X = mon_product(X,X, n, n_inv,r)
        if (exp >> i) & 1:
            X = mon_product(M,X, n, n_inv,r)
    x = mon_product(X,1, n, n_inv,r)
    return x




# # Example usage:
# a = 9112655597874655748395
# e = 23368538474983658027504
# n = 317973638576439257895405
# # r = 2 ** (len(bin(n)) - 2) # r = 2^(number of bits in n)
# r = 1
# while r < n:
#     r <<= 1

# print(montgomery_modular_exponentiation(a,e,n))
# print(power(a,e,n))
# print(mon_mod_exp(a,e,n,r))

###############################################
# the following test proved that egcd functions are correct
# for i in range(10):
#     a = random.randint(0,30)
#     b = random.randint(0,40)
#     print(a,b)
#     print(egcd(a,b))
#     print(gcdExtended(a,b))
#     print(extended_gcd(a,b))
#     print("-----------------------------------------")



###############################################
# the following test proves that MonPro has been fixed
# monPro_test = {(3,3):3, (8,8):4, (4,4):1, (7,7):12, (8,3):8, (8,1):7}
# n=13
# r = 1
# while r < n:
#     r <<= 1
# # print(r,n)
# n_inv = find_n_inv(n,r)
# # print("n_inv is", n_inv)
# # print("It should be r_inv=9 and n_inv=11")
# for key in monPro_test:   
#     print(key)
#     ans = mon_product(key[0],key[1], n, n_inv, r)
#     print(key, ":", ans)
#     print(key, ":", monPro_test[key])
#     print(ans == monPro_test[key])
#     print("-----------------------------------------")

######################################################
# testing miller rabin test
######################################################
# nums = [3,4,7,19,23,15,65,17,13,31]
# for n in nums:
#     print(n, end=" - ")
#     r = 1
#     while r < n:
#         r <<= 1
#     print(miller_rabin_test(n,r))