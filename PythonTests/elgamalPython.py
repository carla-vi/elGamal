from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import secrets

def generate_elgamal_keys(bits):
    print("Generando parámetros para ElGamal...")
    p = getPrime(bits, randfunc=secrets.token_bytes)
    g = 2  # Un generador simple
    x = bytes_to_long(secrets.token_bytes(bits // 8 - 1)) % (p - 1) + 1  # Clave privada
    y = pow(g, x, p)  # Clave pública
    print(f"Primo p: {p}")
    print(f"Generador g: {g}")
    print(f"Clave privada x: {x}")
    print(f"Clave pública y: {y}")
    return p, g, y, x

def elgamal_encrypt(p, g, y, m):
    print("\nAlice quiere enviar un mensaje a Bob.")
    print("Generando una clave efímera aleatoria k...")
    k = bytes_to_long(secrets.token_bytes(16)) % (p - 1) + 1  # Clave efímera aleatoria
    print(f"Clave efímera k: {k}")
    print("Calculando c1 = g^k mod p...")
    c1 = pow(g, k, p)
    print(f"c1: {c1}")
    print("Calculando c2 = m * y^k mod p...")
    yk = pow(y, k, p)
    c2 = (m * yk) % p
    print(f"y^k mod p: {yk}")
    print(f"c2: {c2}")
    print("Mensaje encriptado (c1, c2) enviado a Bob.")
    return c1, c2

def elgamal_decrypt(p, x, c1, c2):
    print("\nBob recibe el mensaje encriptado y quiere desencriptarlo.")
    print("Calculando s = c1^x mod p...")
    s = pow(c1, x, p)
    print(f"s: {s}")
    print("Calculando el inverso modular de s...")
    s_inv = inverse(s, p)
    print(f"s_inv: {s_inv}")
    print("Calculando el mensaje original m = c2 * s_inv mod p...")
    m = (c2 * s_inv) % p
    print("Mensaje desencriptado.")
    return m

def uint64_array_to_str(arr):
    return ', '.join(f'0x{val:016x}' for val in arr)

# Generar claves ElGamal
bits = 1024
p, g, y, x = generate_elgamal_keys(bits)

# Mensaje como un arreglo de uint64_t
m_array = [
    0xcb627fa7ca9f6dc5, 0xd2f916bf786ff86a, 0x7b971a9a5dc03513, 0x4d565469dde369b4,
    0x89438c54e229e8af, 0xa1fe4568ce3bcf12, 0x1b37bbfec006c4b1, 0x5690a6e362b10898,
    0x02ff354862b9ff60, 0x6d288937adc87ea2, 0x92b0997584e05735, 0xb1059f4807574971,
    0x4f6adf6b0863b3a4, 0x655227b338170a10, 0x6054e1fc8d0c9d0a, 0x008c49cbc8fb8c2d,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
]

# Convertir el mensaje a un solo número largo
m_bytes = b''.join(val.to_bytes(8, 'big') for val in m_array)
m = int.from_bytes(m_bytes, 'big')
print(f"\nMensaje original en formato uint64_t: {uint64_array_to_str(m_array)}")
print(f"Mensaje original en bytes: {m_bytes.hex()}")

# Encriptar el mensaje
c1, c2 = elgamal_encrypt(p, g, y, m)
print(f"\nMensaje encriptado c1: {c1}")
print(f"Mensaje encriptado c2: {c2}")

# Desencriptar el mensaje
decrypted_m = elgamal_decrypt(p, x, c1, c2)

# Asegurarnos de que el mensaje desencriptado tenga el tamaño correcto
# Ajuste para el tamaño correcto de bytes
expected_length = 160
decrypted_m_bytes = decrypted_m.to_bytes((decrypted_m.bit_length() + 7) // 8, 'big').rjust(expected_length, b'\0')
decrypted_m_array = [int.from_bytes(decrypted_m_bytes[i:i+8], 'big') for i in range(0, expected_length, 8)]

print(f"\nMensaje desencriptado en formato uint64_t: {uint64_array_to_str(decrypted_m_array)}")
print(f"Mensaje desencriptado en bytes: {decrypted_m_bytes.hex()}")

# Verificar si el mensaje original y desencriptado son iguales
if m_bytes == decrypted_m_bytes:
    print("\nEl mensaje desencriptado coincide con el mensaje original.")
else:
    print("\nEl mensaje desencriptado NO coincide con el mensaje original.")
