#include "elGamalBigInt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// Function to calculate the modular exponentiation: base^exp % mod for 1024-bit numbers
void mod_exp_1024(uint64_t res[], uint64_t base[], uint64_t exp[], uint64_t mod[], uint32_t n) {
    uint64_t result[NUM_WORDS] = {0}, temp_exp[NUM_WORDS] = {0};
    uint64_t mod_base[NUM_WORDS] = {0};
    memcpy(temp_exp, exp, n * sizeof(uint64_t));
    memcpy(mod_base, base, n * sizeof(uint64_t));
    result[0] = 1;

    printf("Starting modular exponentiation...\n");

    while (bit_length(temp_exp, n) > 0) {
        if (temp_exp[0] & 1) {
            printf("Multiplying result by mod_base\n");
            modmult1024(result, result, mod_base, mod, n);
        }
        printf("Squaring mod_base\n");
        modmult1024(mod_base, mod_base, mod_base, mod, n);
        printf("Shifting temp_exp right\n");
        srnbignum(temp_exp, temp_exp, n, 1);
    }

    memcpy(res, result, n * sizeof(uint64_t));
    printf("Modular exponentiation complete.\n");
}

// Function to generate ElGamal key pairs
void generate_keys(uint64_t p[], uint64_t g[], uint64_t x[], uint64_t y[], uint32_t n) {
    printf("Generating prime p and generator g...\n");
    // Prime number (p)
    p[0] = 0xFFFFFFFFFFFFFFFF;  // Example large prime number (256 bits here, expand for 1024)
    p[1] = 0xFFFFFFFFFFFFFFFF;
    p[2] = 0xFFFFFFFFFFFFFFFF;
    p[3] = 0xFFFFFFFFFFFFFFFF;
    // Initialize remaining bits to 0
    memset(&p[4], 0, (n-4) * sizeof(uint64_t));

    // Generator (g)
    g[0] = 2;
    memset(&g[1], 0, (n-1) * sizeof(uint64_t));

    printf("Generating private key x...\n");
    // Private key (x)
    rand_1024(x, n);

    printf("Generating public key y...\n");
    // Public key (y = g^x % p)
    mod_exp_1024(y, g, x, p, n);
    printf("Key generation complete.\n");
}

// Function to encrypt a message
void encrypt(uint64_t c1[], uint64_t c2[], uint64_t p[], uint64_t g[], uint64_t y[], uint64_t m[], uint32_t n) {
    printf("Generating random ephemeral key...\n");
    uint64_t k[NUM_WORDS] = {0};
    rand_1024(k, n);  // Random ephemeral key
    printf("Computing c1 = g^k mod p...\n");
    mod_exp_1024(c1, g, k, p, n);  // c1 = g^k % p
    uint64_t temp[NUM_WORDS] = {0};
    printf("Computing temp = y^k mod p...\n");
    mod_exp_1024(temp, y, k, p, n);  // temp = y^k % p
    printf("Computing c2 = (m * temp) mod p...\n");
    modmult1024(c2, m, temp, p, n);  // c2 = (m * temp) % p
    printf("Encryption complete.\n");
}

// Function to compute modular inverse of a number for 1024-bit numbers
void mod_inverse_1024(uint64_t res[], uint64_t a[], uint64_t mod[], uint32_t n) {
    int64_t x0 = 1, x1 = 0, m0 = (int64_t)mod[0], a0 = (int64_t)a[0];
    while (a0 > 1) {
        int64_t q = a0 / m0, t = m0;
        m0 = a0 % m0;
        a0 = t;
        t = x1;
        x1 = x0 - q * x1;
        x0 = t;
    }
    if (x0 < 0) x0 += mod[0];
    res[0] = (uint64_t)x0;
}

// Function to decrypt a message
void decrypt(uint64_t m[], uint64_t p[], uint64_t x[], uint64_t c1[], uint64_t c2[], uint32_t n) {
    printf("Computing s = c1^x mod p...\n");
    uint64_t s[NUM_WORDS] = {0};
    mod_exp_1024(s, c1, x, p, n);  // s = c1^x % p
    printf("Computing s_inv = s^-1 mod p...\n");
    uint64_t s_inv[NUM_WORDS] = {0};
    mod_inverse_1024(s_inv, s, p, n);  // s_inv = s^-1 % p
    printf("Computing m = (c2 * s_inv) mod p...\n");
    modmult1024(m, c2, s_inv, p, n);  // m = (c2 * s_inv) % p
    printf("Decryption complete.\n");
}

// Function to generate random 1024-bit number
void rand_1024(uint64_t res[], uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        res[i] = ((uint64_t)rand() << 32) | rand();
    }
}

// Helper functions
bool addbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n) {
    uint32_t i;
    uint64_t carry = 0;
    for (i = 0; i < n; i++) {
        uint64_t temp = op1[i] + carry;
        carry = (temp < op1[i]);
        res[i] = temp + op2[i];
        carry |= (res[i] < temp);
    }
    return carry;
}

bool subbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n) {
    uint32_t i;
    uint64_t borrow = 0;
    for (i = 0; i < n; i++) {
        uint64_t temp = op1[i] - op2[i];
        res[i] = temp - borrow;
        borrow = (op1[i] < op2[i]) || (temp < borrow);
    }
    return borrow;
}

bool multbignum(uint64_t res[], uint64_t op1[], uint32_t op2, uint32_t n) {
    uint32_t i;
    uint64_t carry = 0;
    for (i = 0; i < n; i++) {
        uint64_t temp = (op1[i] & 0xFFFFFFFF) * op2 + carry;
        uint64_t high = (op1[i] >> 32) * op2 + (temp >> 32);
        res[i] = (high << 32) | (temp & 0xFFFFFFFF);
        carry = high >> 32;
    }
    res[n] = carry;
    return 0;
}

bool modmult1024(uint64_t res[], uint64_t op1[], uint64_t op2[], uint64_t mod[], uint32_t n) {
    uint64_t mult1[NUM_WORDS] = {0}, mult2[NUM_WORDS] = {0}, result[NUM_WORDS] = {0}, xmod[NUM_WORDS] = {0};
    memcpy(xmod, mod, n * sizeof(uint64_t));

    for (uint32_t i = 0; i < n; i++) {
        memset(mult1, 0, NUM_WORDS * sizeof(uint64_t));
        memset(mult2, 0, NUM_WORDS * sizeof(uint64_t));

        multbignum(mult1, op1, (op2[i] & 0xFFFFFFFF), n);
        multbignum(mult2, op1, (op2[i] >> 32), n);
        slnbignum(mult2, mult2, n + 1, 32);
        addbignum(mult2, mult2, mult1, n + 1);
        slnbignum(mult2, mult2, n + 1, 64 * i);
        addbignum(result, result, mult2, n + 1);
    }

    modbignum(result, result, xmod, n + 1);
    memcpy(res, result, n * sizeof(uint64_t));
    return 0;
}

bool modbignum(uint64_t res[],uint64_t op1[], uint64_t op2[],uint32_t n)//optimized
{
    uint32_t i;
    int32_t len_op1,len_op2,len_dif;

    len_op1 = bit_length(op1,n);
    len_op2 = bit_length(op2,n);
    len_dif = len_op1 - len_op2;

    for(i=0;i<n;i++)
        res[i]=op1[i];

    if(len_dif < 0)
    {
        return 1;
    }

    if(len_dif == 0)
    {
        while(compare(res,op2,n)>=0)
        {
            subbignum(res,res,op2,n);
        }
        return 1;
    }

    slnbignum(op2,op2,n,len_dif);
    for(i=0;i<len_dif;i++)
    {
        srnbignum(op2,op2,n,1);
        while(compare(res,op2,n)>=0)
        {
            subbignum(res,res,op2,n);
        }
    }

    return 1;
}

bool slnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n) {
    printf("slnbignum called with len = %u, n = %u\n", len, n);
    uint32_t x = n / 64, y = n % 64;

    // Check if the shift amount x is larger than the length
    if (x >= len) {
        printf("Shift amount x is greater than or equal to length, setting result to 0\n");
        memset(res, 0, len * sizeof(uint64_t));
        return 1;
    }

    // Shift the op array left by x words
    for (uint32_t i = len; i > x; i--) {
        res[i - 1] = op[i - 1 - x];
    }

    // Zero the lower x words
    for (uint32_t i = x; i > 0; i--) {
        res[i - 1] = 0;
    }

    uint64_t carry = 0;
    for (uint32_t i = 0; i < len; i++) {
        uint64_t temp = res[i];
        res[i] = (temp << y) | carry;
        carry = temp >> (64 - y);
    }

    printf("slnbignum finished\n");
    return 1;
}

bool srnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n) {
    uint32_t x = n / 64, y = n % 64;
    for (uint32_t i = 0; i + x < len; i++) {
        res[i] = op[i + x];
    }
    for (uint32_t i = len - x; i < len; i++) {
        res[i] = 0;
    }
    uint64_t carry = 0;
    for (uint32_t i = len; i > 0; i--) {
        uint64_t temp = res[i - 1];
        res[i - 1] = (temp >> y) | carry;
        carry = temp << (64 - y);
    }
    return 1;
}

uint32_t bit_length(uint64_t op[],uint32_t n)
{
    uint32_t len=0;
    uint32_t i;
    uint64_t unit = 1;
    for( ;n>0;n--)
    {
        if(op[n-1]==0)
            continue;
        for(i=64;i>0;i--)
        {
            if(op[n-1] & (unit<<(i-1)))
            {
                len = (64*(n-1)) + i;
                break;
            }

        }
        if(len)
            break;
    }
    return len;
}

int32_t compare(uint64_t op1[], uint64_t op2[], uint32_t n) {
    for (uint32_t i = n; i > 0; i--) {
        if (op1[i - 1] > op2[i - 1]) return 1;
        if (op1[i - 1] < op2[i - 1]) return -1;
    }
    return 0;
}