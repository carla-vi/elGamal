import random
import math
import sys

class PrivateKey(object):
    def __init__(self, p=None, g=None, x=None, iNumBits=0):
        self.p = p
        self.g = g
        self.x = x
        self.iNumBits = iNumBits

class PublicKey(object):
    def __init__(self, p=None, g=None, h=None, iNumBits=0):
        self.p = p
        self.g = g
        self.h = h
        self.iNumBits = iNumBits

# Computes the greatest common denominator of a and b.  Assumes a > b
def gcd(a, b):
    while b != 0:
        c = a % b
        a = b
        b = c
    # a is returned if b == 0
    return a

# Computes base^exp mod modulus
def modexp(base, exp, modulus):
    return pow(base, exp, modulus)

# Solovay-Strassen primality test.  Tests if num is prime
def SS(num, iConfidence):
    # Ensure confidence of t
    for i in range(iConfidence):
        # Choose random a between 1 and n-2
        a = random.randint(1, num-1)

        # If a is not relatively prime to n, n is composite
        if gcd(a, num) > 1:
            return False

        # Declares n prime if jacobi(a, n) is congruent to a^((n-1)/2) mod n
        if not jacobi(a, num) % num == modexp(a, (num-1)//2, num):
            return False

    # If there have been t iterations without failure, num is believed to be prime
    return True

# Computes the jacobi symbol of a, n
def jacobi(a, n):
    if a == 0:
        if n == 1:
            return 1
        else:
            return 0
    elif a == -1:
        if n % 2 == 0:
            return 1
        else:
            return -1
    elif a == 1:
        return 1
    elif a == 2:
        if n % 8 == 1 or n % 8 == 7:
            return 1
        elif n % 8 == 3 or n % 8 == 5:
            return -1
    elif a >= n:
        return jacobi(a % n, n)
    elif a % 2 == 0:
        return jacobi(2, n) * jacobi(a//2, n)
    else:
        if a % 4 == 3 and n % 4 == 3:
            return -1 * jacobi(n, a)
        else:
            return jacobi(n, a)

# Finds a primitive root for prime p
def find_primitive_root(p):
    if p == 2:
        return 1
    p1 = 2
    p2 = (p-1) // p1
    while True:
        g = random.randint(2, p-1)
        if not (modexp(g, (p-1)//p1, p) == 1):
            if not modexp(g, (p-1)//p2, p) == 1:
                return g

# Find n bit prime
def find_prime(iNumBits, iConfidence):
    while True:
        p = random.randint(2**(iNumBits-2), 2**(iNumBits-1))
        while p % 2 == 0:
            p = random.randint(2**(iNumBits-2), 2**(iNumBits-1))

        while not SS(p, iConfidence):
            p = random.randint(2**(iNumBits-2), 2**(iNumBits-1))
            while p % 2 == 0:
                p = random.randint(2**(iNumBits-2), 2**(iNumBits-1))

        p = p * 2 + 1
        if SS(p, iConfidence):
            return p

# Encodes bytes to integers mod p. Reads bytes from file
def encode(sPlaintext, iNumBits):
    byte_array = bytearray(sPlaintext, 'utf-16')
    z = []
    k = iNumBits // 8
    j = -1 * k
    num = 0
    for i in range(len(byte_array)):
        if i % k == 0:
            j += k
            num = 0
            z.append(0)
        z[j//k] += byte_array[i] * (2**(8*(i%k)))
    return z

# Decodes integers to the original message bytes
def decode(aiPlaintext, iNumBits):
    bytes_array = []
    k = iNumBits // 8
    for num in aiPlaintext:
        for i in range(k):
            temp = num
            for j in range(i+1, k):
                temp = temp % (2**(8*j))
            letter = temp // (2**(8*i))
            bytes_array.append(letter)
            num = num - (letter*(2**(8*i)))
    decodedText = bytearray(b for b in bytes_array).decode('utf-16')
    return decodedText

# Generates public key K1 (p, g, h) and private key K2 (p, g, x)
def generate_keys(iNumBits=256, iConfidence=32):
    print("Generating ElGamal keys...")
    p = find_prime(iNumBits, iConfidence)
    print(f"Found prime p: {p}")
    g = find_primitive_root(p)
    g = modexp(g, 2, p)
    x = random.randint(1, (p - 1) // 2)
    h = modexp(g, x, p)
    publicKey = PublicKey(p, g, h, iNumBits)
    privateKey = PrivateKey(p, g, x, iNumBits)
    print(f"Public Key: (p={p}, g={g}, h={h})")
    print(f"Private Key: (p={p}, g={g}, x={x})")
    return {'privateKey': privateKey, 'publicKey': publicKey}

# Encrypts a string sPlaintext using the public key k
def encrypt(key, sPlaintext):
    print("\nEncrypting message...")
    z = encode(sPlaintext, key.iNumBits)
    cipher_pairs = []
    for i in z:
        y = random.randint(0, key.p)
        c = modexp(key.g, y, key.p)
        d = (i * modexp(key.h, y, key.p)) % key.p
        cipher_pairs.append([c, d])
    encryptedStr = ""
    for pair in cipher_pairs:
        encryptedStr += str(pair[0]) + ' ' + str(pair[1]) + ' '
    print("Encryption complete.")
    return encryptedStr

# Performs decryption on the cipher pairs found in Cipher using
# private key K2 and writes the decrypted values to file Plaintext
def decrypt(key, cipher):
    print("\nDecrypting message...")
    plaintext = []
    cipherArray = cipher.split()
    if not len(cipherArray) % 2 == 0:
        return "Malformed Cipher Text"
    for i in range(0, len(cipherArray), 2):
        c = int(cipherArray[i])
        d = int(cipherArray[i+1])
        s = modexp(c, key.x, key.p)
        plain = (d * modexp(s, key.p-2, key.p)) % key.p
        plaintext.append(plain)
    decryptedText = decode(plaintext, key.iNumBits)
    decryptedText = "".join([ch for ch in decryptedText if ch != '\x00'])
    print("Decryption complete.")
    return decryptedText

def test():
    assert sys.version_info >= (3,4)
    keys = generate_keys()
    priv = keys['privateKey']
    pub = keys['publicKey']
    message = "My name is Ryan. Here is some french text: Maître Corbeau, sur un arbre perché. Now some Chinese: 鋈 晛桼桾 枲柊氠 藶藽 歾炂盵 犈犆犅 壾, 軹軦軵 寁崏庲 摮 蟼襛 蝩覤 蜭蜸覟 駽髾髽 忷扴汥 "
    print(f"Original message: {message}")
    cipher = encrypt(pub, message)
    print(f"Cipher: {cipher}")
    plain = decrypt(priv, cipher)
    print(f"Decrypted message: {plain}")
    return message == plain

if __name__ == "__main__":
    if test():
        print("Test passed: The original message and the decrypted message are the same.")
    else:
        print("Test failed: The original message and the decrypted message are not the same.")
