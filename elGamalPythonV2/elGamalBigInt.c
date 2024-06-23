#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <gmp.h>

typedef struct {
    mpz_t p, g, x;
    int iNumBits;
} PrivateKey;

typedef struct {
    mpz_t p, g, h;
    int iNumBits;
} PublicKey;

void gcd(mpz_t result, mpz_t a, mpz_t b) {
    mpz_t temp;
    mpz_init(temp);

    while (mpz_cmp_ui(b, 0) != 0) {
        mpz_mod(temp, a, b);
        mpz_set(a, b);
        mpz_set(b, temp);
    }

    mpz_set(result, a);
    mpz_clear(temp);
}

void modexp(mpz_t result, mpz_t base, mpz_t exp, mpz_t modulus) {
    mpz_powm(result, base, exp, modulus);
}

int SS(mpz_t num, int iConfidence) {
    mpz_t a, gcd_res, temp, mod_res, exp;
    mpz_init(a);
    mpz_init(gcd_res);
    mpz_init(temp);
    mpz_init(mod_res);
    mpz_init(exp);

    for (int i = 0; i < iConfidence; i++) {
        mpz_urandomm(a, state, num);
        mpz_add_ui(a, a, 1);
        gcd(gcd_res, a, num);
        if (mpz_cmp_ui(gcd_res, 1) > 0) {
            mpz_clears(a, gcd_res, temp, mod_res, exp, NULL);
            return 0;
        }

        mpz_sub_ui(temp, num, 1);
        mpz_div_ui(exp, temp, 2);
        modexp(mod_res, a, exp, num);
        if (mpz_cmp(mod_res, jacobi(a, num)) != 0) {
            mpz_clears(a, gcd_res, temp, mod_res, exp, NULL);
            return 0;
        }
    }

    mpz_clears(a, gcd_res, temp, mod_res, exp, NULL);
    return 1;
}

int jacobi(mpz_t a, mpz_t n) {
    int result = 1;
    mpz_t temp_a, temp_n, temp;
    mpz_init_set(temp_a, a);
    mpz_init_set(temp_n, n);
    mpz_init(temp);

    if (mpz_cmp_ui(a, 0) == 0) {
        result = (mpz_cmp_ui(n, 1) == 0) ? 1 : 0;
    } else if (mpz_cmp_ui(a, -1) == 0) {
        result = (mpz_even_p(n)) ? 1 : -1;
    } else if (mpz_cmp_ui(a, 1) == 0) {
        result = 1;
    } else if (mpz_cmp_ui(a, 2) == 0) {
        int n_mod8 = mpz_mod_ui(temp, n, 8);
        if (n_mod8 == 1 || n_mod8 == 7) {
            result = 1;
        } else if (n_mod8 == 3 || n_mod8 == 5) {
            result = -1;
        }
    } else if (mpz_cmp(a, n) >= 0) {
        mpz_mod(temp_a, a, n);
        result = jacobi(temp_a, n);
    } else if (mpz_even_p(a)) {
        mpz_divexact_ui(temp_a, a, 2);
        result = jacobi(temp_a, n) * jacobi(a, n);
    } else {
        if (mpz_mod_ui(temp_a, n, 4) == 3 && mpz_mod_ui(temp_n, n, 4) == 3) {
            result = -jacobi(n, a);
        } else {
            result = jacobi(n, a);
        }
    }

    mpz_clears(temp_a, temp_n, temp, NULL);
    return result;
}

void find_primitive_root(mpz_t result, mpz_t p) {
    mpz_t p1, p2, g, temp1, temp2;
    mpz_init_set_ui(p1, 2);
    mpz_init(p2);
    mpz_sub_ui(p2, p, 1);
    mpz_divexact(p2, p2, p1);

    mpz_init(g);
    mpz_init(temp1);
    mpz_init(temp2);

    while (1) {
        mpz_urandomm(g, state, p);
        mpz_add_ui(g, g, 2);
        modexp(temp1, g, p1, p);
        if (mpz_cmp_ui(temp1, 1) != 0) {
            modexp(temp2, g, p2, p);
            if (mpz_cmp_ui(temp2, 1) != 0) {
                mpz_set(result, g);
                break;
            }
        }
    }

    mpz_clears(p1, p2, g, temp1, temp2, NULL);
}

void find_prime(mpz_t result, int iNumBits, int iConfidence) {
    mpz_t p, temp;
    mpz_init(p);
    mpz_init(temp);

    while (1) {
        mpz_urandomb(p, state, iNumBits - 1);
        mpz_setbit(p, iNumBits - 1);
        mpz_setbit(p, 0);
        if (SS(p, iConfidence)) {
            mpz_mul_ui(temp, p, 2);
            mpz_add_ui(temp, temp, 1);
            if (SS(temp, iConfidence)) {
                mpz_set(result, temp);
                break;
            }
        }
    }

    mpz_clears(p, temp, NULL);
}

void encode(mpz_t *result, const char *sPlaintext, int iNumBits, int *len) {
    printf("Encoding message: %s\n", sPlaintext);

    int k = iNumBits / 8;
    int j = -k;
    int num = 0;
    int byte_array_len = strlen(sPlaintext) * 2;
    unsigned char *byte_array = (unsigned char *)sPlaintext;

    for (int i = 0; i < byte_array_len; i++) {
        if (i % k == 0) {
            j += k;
            num = 0;
            mpz_init(result[j / k]);
        }
        mpz_add_ui(result[j / k], result[j / k], byte_array[i] * (1 << (8 * (i % k))));
    }

    *len = j / k + 1;
    printf("Encoded message: ");
    for (int i = 0; i < *len; i++) {
        gmp_printf("%Zd ", result[i]);
    }
    printf("\n");
}

void decode(char *result, mpz_t *aiPlaintext, int iNumBits, int len) {
    printf("Decoding message: ");
    for (int i = 0; i < len; i++) {
        gmp_printf("%Zd ", aiPlaintext[i]);
    }
    printf("\n");

    int k = iNumBits / 8;
    int byte_array_len = k * len;
    unsigned char *byte_array = (unsigned char *)malloc(byte_array_len);
    memset(byte_array, 0, byte_array_len);

    for (int idx = 0, i = 0; i < len; i++) {
        for (int j = 0; j < k; j++, idx++) {
            byte_array[idx] = (unsigned char)mpz_get_ui(aiPlaintext[i] >> (8 * j));
        }
    }

    strcpy(result, (char *)byte_array);
    free(byte_array);

    printf("Decoded message: %s\n", result);
}

void generate_keys(PublicKey *publicKey, PrivateKey *privateKey, int iNumBits, int iConfidence) {
    printf("Generating keys...\n");

    mpz_t p, g, x, h;
    mpz_inits(p, g, x, h, NULL);

    find_prime(p, iNumBits, iConfidence);
    find_primitive_root(g, p);
    modexp(g, g, 2, p);
    mpz_urandomm(x, state, p);
    mpz_add_ui(x, x, 1);
    modexp(h, g, x, p);

    mpz_init_set(publicKey->p, p);
    mpz_init_set(publicKey->g, g);
    mpz_init_set(publicKey->h, h);
    publicKey->iNumBits = iNumBits;

    mpz_init_set(privateKey->p, p);
    mpz_init_set(privateKey->g, g);
    mpz_init_set(privateKey->x, x);
    privateKey->iNumBits = iNumBits;

    gmp_printf("Public key: (p=%Zd, g=%Zd, h=%Zd)\n", publicKey->p, publicKey->g, publicKey->h);
    gmp_printf("Private key: (p=%Zd, g=%Zd, x=%Zd)\n", privateKey->p, privateKey->g, privateKey->x);

    mpz_clears(p, g, x, h, NULL);
}

void encrypt(char *encryptedStr, PublicKey *key, const char *sPlaintext) {
    printf("Encrypting message: %s\n", sPlaintext);

    int z_len;
    mpz_t *z = (mpz_t *)malloc(sizeof(mpz_t) * (strlen(sPlaintext) * 2 / (key->iNumBits / 8) + 1));
    encode(z, sPlaintext, key->iNumBits, &z_len);

    mpz_t c, d, y;
    mpz_inits(c, d, y, NULL);

    for (int i = 0; i < z_len; i++) {
        mpz_urandomm(y, state, key->p);
        modexp(c, key->g, y, key->p);
        modexp(d, key->h, y, key->p);
        mpz_mul(d, d, z[i]);
        mpz_mod(d, d, key->p);
        gmp_sprintf(encryptedStr + strlen(encryptedStr), "%Zd %Zd ", c, d);
    }

    printf("Encrypted message: %s\n", encryptedStr);

    mpz_clears(c, d, y, NULL);
    for (int i = 0; i < z_len; i++) {
        mpz_clear(z[i]);
    }
    free(z);
}

void decrypt(char *decryptedStr, PrivateKey *key, const char *cipher) {
    printf("Decrypting message: %s\n", cipher);

    char *token;
    int num_pairs = 0;
    mpz_t *c = (mpz_t *)malloc(sizeof(mpz_t) * strlen(cipher));
    mpz_t *d = (mpz_t *)malloc(sizeof(mpz_t) * strlen(cipher));

    token = strtok(cipher, " ");
    while (token != NULL) {
        mpz_init_set_str(c[num_pairs], token, 10);
        token = strtok(NULL, " ");
        mpz_init_set_str(d[num_pairs], token, 10);
        token = strtok(NULL, " ");
        num_pairs++;
    }

    mpz_t s, plain;
    mpz_inits(s, plain, NULL);

    mpz_t *plaintext = (mpz_t *)malloc(sizeof(mpz_t) * num_pairs);
    for (int i = 0; i < num_pairs; i++) {
        modexp(s, c[i], key->x, key->p);
        modexp(s, s, key->p - 2, key->p);
        mpz_mul(plain, d[i], s);
        mpz_mod(plain, plain, key->p);
        mpz_init_set(plaintext[i], plain);
    }

    decode(decryptedStr, plaintext, key->iNumBits, num_pairs);

    mpz_clears(s, plain, NULL);
    for (int i = 0; i < num_pairs; i++) {
        mpz_clears(c[i], d[i], plaintext[i], NULL);
    }
    free(c);
    free(d);
    free(plaintext);

    printf("Decrypted message: %s\n", decryptedStr);
}

void test() {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    PublicKey publicKey;
    PrivateKey privateKey;
    generate_keys(&publicKey, &privateKey, 256, 32);

    const char *message = "1234567890";
    char cipher[4096] = {0};
    char decryptedMessage[4096] = {0};

    encrypt(cipher, &publicKey, message);
    decrypt(decryptedMessage, &privateKey, cipher);

    printf("Original message: %s\n", message);
    printf("Decrypted message: %s\n", decryptedMessage);

    if (strcmp(message, decryptedMessage) == 0) {
        printf("Test passed: The original message and decrypted message match.\n");
    } else {
        printf("Test failed: The original message and decrypted message do not match.\n");
}

int main() {
    test();
    return 0;
}
