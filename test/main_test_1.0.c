//test_phase1_0.c — Main de test de la phase 1.0 
//Usage : ./test_phase1_0 [nb_paires]


#include <stdio.h>
#include <stdlib.h>
#include "rsa_common_header.h"   // Pour rsaKey_t et MAXPRIME
#include "phase1.h"

/* T1 — Exemple du cours : (33,3) / (33,7), M=4 -> C=31 -> 4 */
static int test_exemple_cours(void)
{
    int echecs = 0;
    /* TODO : inputKey, chiffrer 4, vérifier 31, déchiffrer, vérifier 4 */
    return echecs;
}

/* T2 — Génération et affichage d'une paire de clefs (point 3) */
static int test_generation_affichage(void)
{
    int echecs = 0;
    /* TODO : genKeysRabin, afficher la paire, vérifier N identique et N > 255 */
    return echecs;
}

/* T3 — Affichage hexadécimal (point 2) */
    test_affichage_hexa(rsaKey_t key, const char* keyName)
{
    printKeyHexa(key, keyName);
}

/* T4 — Sauvegarde / chargement (point 4) -> Pas forcément utile, à voir*/
static int test_sauvegarde_chargement(void)
{
    int echecs = 0;
    /* TODO : save puis load, comparer les clefs ; fichier inexistant / corrompu */
    return echecs;
}

/* T5 — Chiffrement/déchiffrement des octets sur plusieurs paires (points 5 et 6) */
static int test_boucle_paires(int nb_paires)
{
    int echecs = 0;
    /* TODO : pour chaque paire, tester les octets 0..255 (+ un caractère UTF-8 multi-octets) ;
     *        compter paires/octets testés et échecs ;
     *        afficher en fin : RESULT MAXPRIME=... paires=... octets=... echecs=... */
    (void)nb_paires;
    return echecs;
}

int main(int argc, char **argv)
{
    int nb_paires;
    int echecs = 0;

    if (argc > 1) {
    nb_paires = atoi(argv[1]);
    } else {
        nb_paires = 20;
    }

    printf("Tests phase 1.0 (MAXPRIME=%d, nb_paires=%d)\n", (int)MAX_PRIME, nb_paires);

    echecs += test_exemple_cours();
    echecs += test_generation_affichage();
    echecs += test_sauvegarde_chargement();
    echecs += test_boucle_paires(nb_paires);

    printf("Bilan : %d echec(s)\n", echecs);
    if (echecs > 0) {
        return EXIT_FAILURE;
    } else {
        return EXIT_SUCCESS;
    }
}