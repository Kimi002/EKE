from random import randint
from base64 import b64encode
from sympy import primitive_root

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