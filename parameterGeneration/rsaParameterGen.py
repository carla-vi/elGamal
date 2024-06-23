import math

def extended_gcd(a, b):
    """Extended Euclidean Algorithm that returns the gcd of a and b,
    and the coefficients (x, y) such that ax + by = gcd(a, b)."""
    x, last_x, y, last_y = 0, 1, 1, 0
    while b != 0:
        q = a // b
        a, b = b, a % b
        x, last_x = last_x - q * x, x
        y, last_y = last_y - q * y, y
    return last_x, last_y

def modinv(a, m):
    """Return the modular inverse of a under modulo m."""
    x, _ = extended_gcd(a, m)
    return x % m

def generate_rsa_keys(p, q):
    """Generate RSA modulus, public exponent, and private exponent given two primes."""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common choice for e
    d = modinv(e, phi)
    return n, e, d

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

# Example prime numbers (You should use large primes for a real scenario)
p = 184341136709932551689232331587242762362157908480432120025755702381107447833142994565159238926414107693349085366713513698511825160166039592035736712784361
q = 2087539561466647802589261891882958601018479810313372725202828636853477564694391070475307360531977884304183455067336451084460280530976540176832556805906301


n, e, d = generate_rsa_keys(p, q)

# Format the numbers for a C array with 18 elements per the specifications
print("Modulus (n) Array for C:")
print(format_for_c('n', n, 20))
print("\nPublic Exponent (e) Array for C:")
print(format_for_c('e', e, 18))
print("\nPrivate Exponent (d) Array for C:")
print(format_for_c('d', d, 20))
