/// \file phase1.h
/// \brief prototypes de la phase 1 (outils RSA, chiffrement octets/fichiers, base64)
#ifndef PHASE1_H
#define PHASE1_H

#include <inttypes.h>   // PRIx64, PRIu64, PRId64
#include "rsa_common_header.h"

/* ---------- rsa_tools.c ---------- */
void     erreur(char *msg);
uint64_t random_uint(uint64_t min, uint64_t max);
int      premier(uint64_t n);
int      decompose(uint64_t facteur[], uint64_t n);
uint64_t puissance(uint64_t a, uint64_t e);
uint64_t puissance_mod_n(uint64_t a, uint64_t e, uint64_t n);      // version uint64 (deborde si n > 2^32)
uint64_t puissance_mod_n_sure(uint64_t a, uint64_t e, uint64_t n); // version __int128 (reference)
uint64_t genereUint(uint64_t max, int *cpt);
int      rabin(uint64_t a, uint64_t n);
int      rabin_multi(uint64_t n);
int64_t  genereUintRabin(uint64_t max, int *cpt);
uint64_t pgcdFast(uint64_t a, uint64_t b);
void     genKeysRabin(rsaKey_t *pubKey, rsaKey_t *privKey, uint64_t max_prime);
void     inputKey(uint64_t E, uint64_t N, rsaKey_t *key);
void     verifRabin(uint64_t max, int iterations);

/* ---------- bezout.c ---------- */
int64_t bezout(uint64_t a, uint64_t b, int64_t *u, int64_t *v);
int64_t bezoutRSA(uint64_t a, uint64_t b, int64_t *u, int64_t *v);

/* ---------- int2char.c ---------- */
uint32_t convert_4byte2int(uint8_t *b);
void     convertInt2uchar(uint32_t nb, uint8_t *tab4bytes);

/* ---------- other_base64.c ---------- */
char          *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);
void           base64_cleanup(void);

/* ---------- phase1.c : phases 1.0 a 1.3 ---------- */
void printKey(rsaKey_t key, const char *keyName);
void printKeyPair(keyPair_t kp);
int  saveKeytoFile(keyPair_t keyP, const char *filename);
int  loadKeytoprog(keyPair_t *keyP, const char *filename);
int  testChiffrementOverflow(uint64_t max_prime_test);
int  bilanOverflow(uint64_t max_prime_test, int essais);

void     u64_to_bytes(uint64_t v, uint8_t *b);
uint64_t bytes_to_u64(const uint8_t *b);
size_t   chiffrer_octets(const uint8_t *in, size_t len, rsaKey_t pub, uint8_t *out);
size_t   dechiffrer_octets(const uint8_t *in, size_t len, rsaKey_t priv, uint8_t *out);

int chiffrer_fichier(const char *src, const char *dst, rsaKey_t pub);
int dechiffrer_fichier(const char *src, const char *dst, rsaKey_t priv);

int fichier_vers_base64(const char *src, const char *dst);
int base64_vers_fichier(const char *src, const char *dst);

/* ---------- tests.c ---------- */
int lancer_tous_les_tests(uint64_t max_prime);

#endif