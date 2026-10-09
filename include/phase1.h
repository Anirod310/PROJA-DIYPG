#ifndef PHASE_1
#define PHASE_1


#include "rsa_common_header.h"
#include <inttypes.h>



void printKey(rsaKey_t key, const char* keyName);
int saveKeytoFile(keyPair_t keyP, const char* filename);
int chiffrer_fichier(const char *src, const char *dst, rsaKey_t pub);
int dechiffrer_fichier(const char *src, const char *dst, rsaKey_t priv);




#endif
