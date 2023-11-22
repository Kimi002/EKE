from random import randint
from base64 import b64encode

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