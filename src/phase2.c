/// \file phase2.c
/// \brief phase 2 : chiffrement par blocs de 4 octets avec la bibliotheque GMP
/// \author Bousseksou Dorian, Boillat Clement, Napoletano Ethan, Mokhtari Tahar

#include "phase2.h"

//Conversions uint64 <-> GMP :

/// copie un uint64_t dans un nombre GMP
/// (mpz_set_ui prend un unsigned long, qui ne fait que 32 bits sous Windows :
/// mpz_import marche partout)
void mpz_set_u64(mpz_t z, uint64_t v){
    mpz_import(z, 1, -1, sizeof v, 0, 0, &v);
}

/// renvoie la valeur d'un nombre GMP qui tient sur 64 bits
uint64_t mpz_get_u64(const mpz_t z){
    uint64_t v = 0;                       // si z vaut 0, mpz_export n'ecrit rien
    mpz_export(&v, NULL, -1, sizeof v, 0, 0, z);
    return v;
}

//Calculs :

/// calcule res = a^e mod n avec GMP
/// les calculs intermediaires ne debordent plus : GMP agrandit les nombres si besoin
void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n){
    mpz_t base, exposant, modulo;
    mpz_inits(base, exposant, modulo, NULL);

    mpz_set_u64(base, a);
    mpz_set_u64(exposant, e);
    mpz_set_u64(modulo, n);
    mpz_powm(res, base, exposant, modulo);   // puissance modulaire fournie par GMP

    mpz_clears(base, exposant, modulo, NULL);
}

/// tire un entier de 64 bits au hasard (rand() ne donne que 15 bits garantis : on en assemble 4 x 16)
static uint64_t random_u64(void){
    uint64_t v = 0;
    for (int i = 0; i < 4; i++){
        v = v * 65536 + (rand() % 65536);
    }
    return v;
}

/// met dans p un nombre premier tire au hasard entre 2^16 et max_prime
static void generePremierGMP(mpz_t p, uint64_t max_prime){
    mpz_t depart, borne;
    mpz_inits(depart, borne, NULL);
    mpz_set_u64(borne, max_prime);

    do {
        // point de depart au hasard dans [2^16, max_prime[
        uint64_t hasard = 65536 + random_u64() % (max_prime - 65536);
        mpz_set_u64(depart, hasard);
        mpz_nextprime(p, depart);             // premier nombre premier > depart
    } while (mpz_cmp(p, borne) >= 0);         // on recommence s'il depasse la borne

    mpz_clears(depart, borne, NULL);
}

/// genere une paire de clefs RSA avec GMP
/// \returns 1 si tout va bien, 0 si max_prime est hors limites
/// N doit etre > 2^32 : sinon un bloc de 4 octets (jusqu'a 2^32 - 1) pourrait etre >= N
/// et ne serait pas retrouve au dechiffrement. On prend p et q > 2^16, donc N > 2^32.
/// Avec p, q < 2^32, on a aussi N < 2^64.
int genKeysGMP(rsaKey_t *pubKey, rsaKey_t *privKey, uint64_t max_prime){
    if (max_prime < MIN_PRIME_GMP || max_prime > MAX_PRIME_GMP){
        fprintf(stderr, "genKeysGMP : max_prime doit etre entre %llu et %llu\n",
                (unsigned long long)MIN_PRIME_GMP, (unsigned long long)MAX_PRIME_GMP);
        return 0;
    }

    mpz_t p, q, N, M, C, U, limite, pgcd;
    mpz_inits(p, q, N, M, C, U, limite, pgcd, NULL);
    mpz_set_u64(limite, UINT32_MAX);

    // 1. deux nombres premiers differents, avec N = p*q > 2^32
    do {
        generePremierGMP(p, max_prime);
        generePremierGMP(q, max_prime);
        mpz_mul(N, p, q);
    } while (mpz_cmp(p, q) == 0 || mpz_cmp(N, limite) <= 0);

    // 2. M = (p-1)(q-1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(M, p, q);

    // 3. exposant public C : 65537 (valeur classique), ou l'impair suivant premier avec M
    mpz_set_ui(C, 65537);
    mpz_gcd(pgcd, C, M);
    while (mpz_cmp_ui(pgcd, 1) != 0){
        mpz_add_ui(C, C, 2);
        mpz_gcd(pgcd, C, M);
    }

    // 4. exposant prive U : inverse de C modulo M (remplace bezoutRSA)
    mpz_invert(U, C, M);

    pubKey->E  = mpz_get_u64(C);
    pubKey->N  = mpz_get_u64(N);
    privKey->E = mpz_get_u64(U);
    privKey->N = mpz_get_u64(N);

    mpz_clears(p, q, N, M, C, U, limite, pgcd, NULL);
    return 1;
}

//Blocs :

/// chiffre un bloc de 4 octets (vu comme un entier) : c = bloc^E mod N
/// \returns le chiffre, < N donc sur 64 bits
uint64_t chiffrer_bloc(uint32_t bloc, rsaKey_t pubKey){
    assert(bloc < pubKey.N);              // toujours vrai si N > 2^32

    mpz_t res;
    mpz_init(res);
    puissance_mod_n_gmp(res, bloc, pubKey.E, pubKey.N);
    uint64_t chiffre = mpz_get_u64(res);
    mpz_clear(res);
    return chiffre;
}

/// dechiffre un bloc : bloc = c^U mod N
/// \returns le bloc de 4 octets d'origine
uint32_t dechiffrer_bloc(uint64_t chiffre, rsaKey_t privKey){
    mpz_t res;
    mpz_init(res);
    puissance_mod_n_gmp(res, chiffre, privKey.E, privKey.N);
    uint64_t bloc = mpz_get_u64(res);     // < 2^32 si la bonne clef est utilisee
    mpz_clear(res);
    return (uint32_t)bloc;
}

//Fichiers :
//
// format du fichier chiffre :
//   - 8 octets : taille du fichier clair (pour savoir combien d'octets garder dans le dernier bloc)
//   - puis 8 octets par bloc de 4 octets clairs
// le dernier bloc est complete avec des 0 s'il fait moins de 4 octets

/// chiffre le fichier src par blocs de 4 octets et ecrit le resultat dans dst
/// \returns 1 si tout va bien, 0 en cas d'erreur
int chiffrer_fichier_blocs(const char *src, const char *dst, rsaKey_t pubKey){
    if (pubKey.N <= UINT32_MAX){
        fprintf(stderr, "clef trop petite : il faut N > 2^32 pour des blocs de 4 octets\n");
        return 0;
    }

    FILE *fi = fopen(src, "rb");
    if (fi == NULL){
        perror(src);
        return 0;
    }
    FILE *fo = fopen(dst, "wb");
    if (fo == NULL){
        perror(dst);
        fclose(fi);
        return 0;
    }

    // 1. taille du fichier clair, ecrite en en-tete
    fseek(fi, 0, SEEK_END);
    uint64_t taille = (uint64_t)ftell(fi);
    fseek(fi, 0, SEEK_SET);

    uint8_t entete[8];
    u64_to_bytes(taille, entete);
    fwrite(entete, 1, 8, fo);

    // 2. chiffrer chaque bloc de 4 octets
    uint8_t clair[BLOCK_SIZE];
    uint8_t chiffre[TAILLE_BLOC_CHIFFRE];
    size_t nbLus = fread(clair, 1, BLOCK_SIZE, fi);
    while (nbLus > 0){
        // completer le dernier bloc avec des 0
        for (size_t i = nbLus; i < BLOCK_SIZE; i++){
            clair[i] = 0;
        }
        uint32_t bloc = convert_4byte2int(clair);
        uint64_t c = chiffrer_bloc(bloc, pubKey);
        u64_to_bytes(c, chiffre);

        size_t nbEcrits = fwrite(chiffre, 1, TAILLE_BLOC_CHIFFRE, fo);
        if (nbEcrits != TAILLE_BLOC_CHIFFRE){
            perror(dst);
            fclose(fi);
            fclose(fo);
            return 0;
        }
        nbLus = fread(clair, 1, BLOCK_SIZE, fi);
    }

    fclose(fi);
    if (fclose(fo) != 0){
        perror(dst);
        return 0;
    }
    return 1;
}

/// dechiffre un fichier produit par chiffrer_fichier_blocs et ecrit le resultat dans dst
/// \returns 1 si tout va bien, 0 en cas d'erreur (fichier introuvable, tronque ou abime)
int dechiffrer_fichier_blocs(const char *src, const char *dst, rsaKey_t privKey){
    FILE *fi = fopen(src, "rb");
    if (fi == NULL){
        perror(src);
        return 0;
    }

    // 1. lire la taille du fichier clair
    uint8_t entete[8];
    if (fread(entete, 1, 8, fi) != 8){
        fprintf(stderr, "%s : fichier chiffre trop court\n", src);
        fclose(fi);
        return 0;
    }
    uint64_t reste = bytes_to_u64(entete);   // nombre d'octets clairs encore a ecrire

    FILE *fo = fopen(dst, "wb");
    if (fo == NULL){
        perror(dst);
        fclose(fi);
        return 0;
    }

    // 2. dechiffrer bloc par bloc
    uint8_t chiffre[TAILLE_BLOC_CHIFFRE];
    uint8_t clair[BLOCK_SIZE];
    int ok = 1;
    while (reste > 0 && ok == 1){
        size_t nbLus = fread(chiffre, 1, TAILLE_BLOC_CHIFFRE, fi);
        if (nbLus != TAILLE_BLOC_CHIFFRE){
            fprintf(stderr, "%s : fichier chiffre tronque\n", src);
            ok = 0;
        } else {
            uint32_t bloc = dechiffrer_bloc(bytes_to_u64(chiffre), privKey);
            convertInt2uchar(bloc, clair);

            // le dernier bloc peut contenir des 0 de remplissage : on ne garde que "reste" octets
            size_t aEcrire = BLOCK_SIZE;
            if (reste < BLOCK_SIZE){
                aEcrire = (size_t)reste;
            }
            fwrite(clair, 1, aEcrire, fo);
            reste = reste - aEcrire;
        }
    }

    // 3. il ne doit rien rester apres le dernier bloc
    if (ok == 1 && fgetc(fi) != EOF){
        fprintf(stderr, "%s : donnees en trop a la fin du fichier chiffre\n", src);
        ok = 0;
    }

    fclose(fi);
    if (fclose(fo) != 0){
        perror(dst);
        return 0;
    }
    return ok;
}