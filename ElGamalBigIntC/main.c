#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "elGamalBigInt.h"

void print_hex(const char *label, uint64_t arr[], uint32_t n) {
    printf("%s", label);
    for (int i = n - 1; i >= 0; i--) {
        printf("%016llx", arr[i]);
    }
    printf("\n");
}

int main() {
    srand(time(NULL));

    uint64_t p[NUM_WORDS] = {0}, g[NUM_WORDS] = {0}, x[NUM_WORDS] = {0}, y[NUM_WORDS] = {0};
    
    printf("Generating keys...\n");
    generate_keys(p, g, x, y, NUM_WORDS);
    printf("Keys generated.\n");

    printf("Public key: (p = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", p[i]);
    printf(", g = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", g[i]);
    printf(", y = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", y[i]);
    printf(")\n");

    printf("Private key: x = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", x[i]);
    printf("\n");

    uint64_t message[NUM_WORDS] = {0};
    message[0] = 0x1234567890ABCDEF;  // Example message
    printf("Original message: ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", message[i]);
    printf("\n");

    uint64_t c1[NUM_WORDS] = {0}, c2[NUM_WORDS] = {0};
    printf("Encrypting message...\n");
    encrypt(c1, c2, p, g, y, message, NUM_WORDS);
    printf("Message encrypted.\n");

    printf("Ciphertext: (c1 = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", c1[i]);
    printf(", c2 = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", c2[i]);
    printf(")\n");

    uint64_t decrypted_message[NUM_WORDS] = {0};
    printf("Decrypting message...\n");
    decrypt(decrypted_message, p, x, c1, c2, NUM_WORDS);
    printf("Message decrypted.\n");

    printf("Decrypted message: ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", decrypted_message[i]);
    printf("\n");

    return 0;
}
