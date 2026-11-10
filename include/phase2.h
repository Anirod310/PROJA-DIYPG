/// \file phase2.h
/// \brief Phase 2 : chiffrement par blocs de 4 octets avec GMP
#ifndef PHASE2_H
#define PHASE2_H

#include <gmp.h>
#include <assert.h>
#include "conversions.h"

// Bornes pour que p, q > 2^16 et N = p*q > 2^32 (sur 64 bits)
#define MIN_PRIME_GMP 70000ULL
#define MAX_PRIME_GMP 4294967295ULL   // 2^32 - 1

// 1 bloc clair = 4 octets (BLOCK_SIZE dans rsa_common_header.h) -> 1 bloc chiffre = 8 octets (uint64_t)
#ifndef BLOCK_SIZE
#define BLOCK_SIZE 4
#endif
#define TAILLE_BLOC_CHIFFRE 8

/* ---------- Conversions 4 octets <-> uint32 (fournies) ---------- */
uint32_t convert_4byte2int(uint8_t *b);
void     convertInt2uchar(uint32_t nb, uint8_t *tab4bytes);

/* ---------- Conversions uint64 <-> GMP ---------- */
void     mpz_set_u64(mpz_t z, uint64_t v);
uint64_t mpz_get_u64(const mpz_t z);

/* ---------- Calculs et generation de clefs GMP ---------- */
void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n);
int  genKeysGMP(rsaKey_t *pubKey, rsaKey_t *privKey, uint64_t max_prime);

/* ---------- Chiffrement par blocs de 4 octets ---------- */
uint64_t chiffrer_bloc(uint32_t bloc, rsaKey_t pubKey);
uint32_t dechiffrer_bloc(uint64_t chiffre, rsaKey_t privKey);

int chiffrer_fichier_blocs(const char *src, const char *dst, rsaKey_t pubKey);
int dechiffrer_fichier_blocs(const char *src, const char *dst, rsaKey_t privKey);

#endif