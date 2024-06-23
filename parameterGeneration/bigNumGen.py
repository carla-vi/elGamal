import random

def generate_random_bits(bit_length):
    """Generate a random integer of approximately 'bit_length' bits."""
    return random.randint(2**(bit_length-1), 2**bit_length - 1)

def format_for_c(name, value, array_size):
    """Format a large integer value into a C-style uint64_t array initialization string."""
    chunks = [0] * array_size  # Initialize the array with zeros
    index = 0
    while value > 0 and index < array_size:
        chunks[index] = value & 0xFFFFFFFFFFFFFFFF  # Mask the lowest 64 bits
        value >>= 64  # Right shift by 64 bits to get the next chunk
        index += 1

    # Format the array into a string for C code
    formatted = ', '.join(f'0x{chunk:x}' for chunk in chunks)
    return f'uint64_t {name}[{array_size}] = {{{formatted}}};'

# Number of bits for the random number
bit_length = 1000

# Generate a random 300-bit number
random_number = generate_random_bits(bit_length)

# Format this number for a C uint64_t array with 20 elements
formatted_c_array = format_for_c('data', random_number, 20)
print(formatted_c_array)
