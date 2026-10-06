#ifndef __BC_DEFINES__
#define __BC_DEFINES__
// Header donné à titre indicatif (en clair vous pouvez l'ignorer et faire le vôtre)
//
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "sha256.h"
#include "sha256_utils.h"

#define MAX_BUF 1024
#define MAX_STRING 64
#define MAXTX 5 // nb max tx par bloc (tests)
#define DIFFICULTY 4 // difficulté pour le minage
#define MAX_USERS 5 // nb utilisateurs (tests)
#define HASHLENGTH (SHA256_BLOCK_SIZE*2 + 1)

typedef unsigned char byte;

// structure générique de liste non typée (à typer à l'utilisation)
typedef struct Slist {
	void * info; // les elt sont des blocks ou des transactions, ce qu'on veut en fait
	struct Slist *next;
} Slist;

// structure de bloc
typedef struct block {
	int index; // numéro d'ordre dans la BC
	BYTE previousHash[SHA256_BLOCK_SIZE*2 + 1];
  time_t timestamp;
	int nbTx; // nombre de transaction dans le bloc
	struct Slist * transactions; // liste de tx le nombre doit correspondre
	BYTE merkleTree[SHA256_BLOCK_SIZE*2 + 1]; // hash de l'arbre de Merkle
  BYTE blockHash[SHA256_BLOCK_SIZE*2 + 1]; // hash du bloc courant
  char minerName[MAX_STRING]; // nom du mineur
  char comment[MAX_STRING];
	long nonce;
} Block;

typedef struct s_Blockchain {
  int difficulty; // nombre de zéros initiaux du hash
  int nbBlocks; // nombre de blocs de la Blockchain
	struct Slist * blocklist; // liste des blocks
} Blockchain;

typedef struct transaction {
	BYTE txid[SHA256_BLOCK_SIZE*2 + 1]; // txid = hash(hash(tx))
  time_t timestamp; // date de création
	BYTE adSender[SHA256_BLOCK_SIZE*2 + 1]; // ou nom "user x"
	BYTE adReceiver[SHA256_BLOCK_SIZE*2 + 1]; // idem
  long txAmount; // en token (cryptomonnaie, euronum, USDC, etc.)
	char * typeTx; //
	char * Key; // pubkey
	char * Signature;
	char comment[MAX_STRING];
} Transaction;

typedef struct account {
  char user[MAX_STRING];
	uint32 solde;
} Account;

#endif // __BC_DEFINES__
