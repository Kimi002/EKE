from Crypto.Util.number import getPrime
import random
import math

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

#---------------------------------------------------------
# Euler's totient p is 2*q
# Any number co prime to q (any number between 1 and q) is the generator for group 1 to q
# Take a random, or find the smallest x such that g^2 != 1 and  g^q = 1. Then we have a generator
# Below was my implementation to get DH parameters
# Almost correct

# while True:
# 	q = getPrime(1024)
# 	print(miller_rabin_test(q))
# 	p = get_safe_prime(q)
# 	# print("got p")
# 	if p == -1:
# 		continue
# 	print("modulus =",p)

# 	while True:
# 		g = random.randint(2,p-1)
# 		# BigInteger exp = (p.subtract(BigInteger.ONE)).divide(q); = (p-1)/q = 2
# 		exp = 2
# 		if power(g,2,p) != 1:
# 			break
# 	print(power(g,q,p))
# 	break


# print()
# print(p)
# print()
# print(g)

# The above code is fast
# Problem : Generation of safe prime takes an arbotrary amout of time. Sometimes fast, sometimes very slow


###
# One example output of the program
###
# generated_modulus = 353117934618284949027435136696703781552113932958117486039160205769758805808363939293991246373325312888457313557807982157858925180618841328389153733474057643639328034583090471235691738675768242394327742180172150182986848966269574933122421014233792604960353637763006346039992616366126582167462160277195807022787

# generator = 257913294677268907561434753363294611241533211350298078151488352655909665674252891059240720160863896752546451677203872426749780902823000494645989655298260209882414391635862931507924498719139979949393657142983904495489540711288780199833865926298220634365423384961191657641602565793994009867757083976299941652337


# q = (generated_modulus - 1)
# q = q//2
# print(miller_rabin_test(generated_modulus))
# print(miller_rabin_test(q))
# print(miller_rabin_test(generator))
# print(power(generator, 2, generated_modulus))
# print()
# print(power(generator, q , generated_modulus))
# print()
# print(power(generator, generated_modulus -1 , generated_modulus))

###
# Another example
# mod = 191421130673665762690541583655871577839300471310668993396462315773308312671134702120157628101387956544263037062269415353389312046680873836647897963014688080009841782867247269797655393526793818541094532881503788876789573288682802391453009966288869705890116832960608953381860846096089339196231992644259590440547

# gen = 3457728980314861035470114748969299452132294704810123276839613475212259641261827366782266592876308377687779202083945513110777598728643023041072596863246072040874505958596845888067202653656787959095484188686983691564811427834782636359944260844284805087326638882616845912337139522497329623028538939605190277059


#----------------------------------------------
###
# Corrected version
# generator is a quadratic non residue
# Quadratic non residue has legendre value = -1
# Legendre value = a**((p-1)/2) = a**q

while True:
    q = getPrime(1024)
    # print(miller_rabin_test(q))
    p = get_safe_prime(q)
    # print(miller_rabin_test(p))
	# print("got p")
    if p == -1:
        continue
    print("modulus =",p)
    print(miller_rabin_test(q))
    while True:
        print("hi", end = ",")
        g = random.randint(10,p-1)
		# legendre = g ** ((p-1)/2) (mod p)
        exp = (p-1)//2
        # print(exp==q, end=",")
        if power(g,exp,p) == p-1:
             break
    print()
    print(power(g,q,p))
    print()
    print("g=", g)
    break

with open("./DH_params.txt", "a") as f:
      f.write("p = ")
      f.write(str(p))
      f.write('\n')
      f.write("g = ")
      f.write(str(g))
      f.write('\n')
      f.write("------------------------")
      f.write('\n')