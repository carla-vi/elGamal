import random

def is_prime(n, k=5):
    """Test if a number is prime using Miller-Rabin primality test."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write (n - 1) as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    def miller_rabin_test(a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    for _ in range(k):
        a = random.randrange(2, n - 1)
        if not miller_rabin_test(a):
            return False
    return True

def generate_large_prime(bits):
    """Generate a large prime number of the given bit size."""
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p

def find_primitive_root(p):
    """Find a primitive root for prime p."""
    if p == 2:
        return 1
    p1, p2 = 2, (p - 1) // 2
    while True:
        g = random.randint(2, p - 1)
        if pow(g, (p - 1) // p1, p) != 1 and pow(g, (p - 1) // p2, p) != 1:
            return g

def generate_elgamal_keys(bits):
    """Generate ElGamal parameters: prime p, generator g, private key x, and public key y."""
    p = generate_large_prime(bits)
    g = find_primitive_root(p)
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return p, g, x, y

def format_for_c(name, value, array_size):
    """Format numbers for C array with the given name and size."""
    chunks = [0] * array_size  # Initialize the array with zeros
    for i in range(len(chunks) - 2):  # Reserve the last two indices as zeros for processing
        if value == 0:
            break
        chunks[i] = value & 0xFFFFFFFFFFFFFFFF
        value >>= 64

    formatted = ', '.join(f'0x{chunk:016x}' for chunk in chunks)
    return f'uint64_t {name}[{array_size}] = {{{formatted}}};'

# Example: Generate ElGamal keys with a 512-bit prime (you should use larger primes for real scenarios)
bits = 512
p, g, x, y = generate_elgamal_keys(bits)

# Format the numbers for a C array
print("Prime (p) Array for C:")
print(format_for_c('p', p, 10))
print("\nGenerator (g) Array for C:")
print(format_for_c('g', g, 2))
print("\nPrivate Key (x) Array for C:")
print(format_for_c('x', x, 10))
print("\nPublic Key (y) Array for C:")
print(format_for_c('y', y, 10))