from primes import gen_prime

class DiffieHellman:
    str_dict = {'a': "101", 'b': "102", 'c': "103", 'd': "104", 'e': "105", 'f': "106", 'g': "107", 'h': "108", 
            'i': "109", 'j': "110", 'k': "111", 'l': "112", 'm': "113", 'n': "114", 'o': "115", 'p': "116", 
            'q': "117", 'r': "118", 's': "119", 't': "120", 'u': "121", 'v': "122", 'w': "123", 'x': "124", 
            'y': "125", 'z': "126", " ": "127", 'A': "201", 'B': "202", 'C': "203", 'D': "204", 'E': "205", 
            'F': "206", 'G': "207", 'H': "208", 'I': "209", 'J': "210", 'K': "211", 'L': "212", 'M': "213", 
            'N': "214", 'O': "215", 'P': "216", 'Q': "217", 'R': "218", 'S': "219", 'T': "220", 'U': "221", 
            'V': "222", 'W': "223", 'X': "224", 'Y': "225", 'Z': "226", ",": "301", ".": "302"}
    def __init__(self, a: int, g: int, p: int):
        self.a = a
        self.g = g
        self.p = p
        self.key = (g ** a) % p

    def gen(self):
        # generate public key
        return self.key
    
    
    def decode_public_key(self,r_other):

        self.exchange_key = (r_other ** self.a) % self.p
        return self.exchange_key

    def encrypt_string(self,string_in, secret_key):
        string_as_num = "".join(self.str_dict[string_in[n]] for n in range(0, len(string_in)))

        return int(string_as_num) * secret_key

    def decrypt_string(self,encrypted_str, secret_key):
        string_as_num = str(int(encrypted_str//secret_key))
        start_index = 0
        end_index = 3
        string_out = ""

        for _ in range(0, len(string_as_num)//3):
            string_out += "".join([k for k,v in self.str_dict.items() if v==string_as_num[start_index:end_index]])
            start_index += 3
            end_index += 3

        return string_out
