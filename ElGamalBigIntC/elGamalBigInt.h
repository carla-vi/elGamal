#ifndef ELGAMAL_BIGINT_H
#define ELGAMAL_BIGINT_H

#include <stdint.h>
#include <stdbool.h>

#define NUM_WORDS 10  // Adjusted for 512-bit words as per provided arrays

void mod_exp_1024(uint64_t res[], uint64_t base[], uint64_t exp[], uint64_t mod[], uint32_t n);
void generate_keys(uint64_t p[], uint64_t g[], uint64_t x[], uint64_t y[], uint32_t n);
void encrypt(uint64_t c1[], uint64_t c2[], uint64_t p[], uint64_t g[], uint64_t y[], uint64_t m[], uint32_t n);
void mod_inverse_1024(uint64_t res[], uint64_t a[], uint64_t mod[], uint32_t n);
void decrypt(uint64_t m[], uint64_t p[], uint64_t x[], uint64_t c1[], uint64_t c2[], uint32_t n);
void rand_1024(uint64_t res[], uint32_t n);

bool addbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool subbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool multbignum(uint64_t res[], uint64_t op1[], uint32_t op2, uint32_t n);
bool modmult1024(uint64_t res[], uint64_t op1[], uint64_t op2[], uint64_t mod[], uint32_t n);
bool modbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool slnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n);
bool srnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n);
uint32_t bit_length(uint64_t op[], uint32_t n);
int32_t compare(uint64_t op1[], uint64_t op2[], uint32_t n);

#endif // ELGAMAL_BIGINT_H
