/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding SHA1
	          implementation. These tests do not encompass the full
	          range of available test vectors, however, if the tests
	          pass it is very, very likely that the code is correct
	          and was compiled properly. This code also serves as
	          example usage of the functions.
* Update by VD:
	          Merci Brad. Je modifie le code pour l'adapter au besoins du projet S4

	          J'ajoute les lignes qui transforment le hash en hex car elles manquent

*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
//#include "sha256.h"
#include "sha256_utils.h"

/*********************** FUNCTION DEFINITIONS ***********************/

void sha256ofString(BYTE * str,char hashRes[SHA256_BLOCK_SIZE*2 + 1])
// attention tous vos hash doivent avoir ce format. Char * ne convient pas.
// J'ai perdu deux jours avec cette subtilité
{
  BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
  int bufferSize = SHA256_BLOCK_SIZE;
  //char hashRes[bufferSize*2 + 1];

	sha256_init(&ctx);
	sha256_update(&ctx, str, strlen((char *)str));
	sha256_final(&ctx, buf); // buf contient le hash de str
  //int charCount =0;
  for(int i=0;i<bufferSize;i++) {
        sprintf(&hashRes[i*2], "%02x", buf[i]);
  }
}
