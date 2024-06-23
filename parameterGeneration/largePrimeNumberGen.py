import secrets

def is_prime(n, k=5):  # number of tests
    """ Test if a number is prime using the Miller-Rabin primality test algorithm. """
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n < 2:
        return False

    # write n-1 as 2^s * d
    s = 0
    d = n - 1

    while d % 2 == 0:
        d >>= 1
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 2) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits):
    """ Generate a large prime number of approximately 'bits' bits. """
    prime_candidate = secrets.randbits(bits)
    while not is_prime(prime_candidate):
        prime_candidate = secrets.randbits(bits)
    return prime_candidate

# Example of generating a 1024-bit prime number
large_prime = generate_large_prime(510)
print(f"Large Prime: {large_prime}")