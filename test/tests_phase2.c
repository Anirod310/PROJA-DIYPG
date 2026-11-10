/**
 * \file tests_phase2.c
 * \brief Banc de tests unitaires et d'intégration pour la Phase 2 (DIYPG / RSA).
 * \details Validation de l'arithmétique multiprécision (libgmp), de la génération
 *          des bi-clefs RSA, du découpage et chiffrement par blocs de 4 octets,
 *          des I/O binaires, de l'encodage Base64 et des formats d'export.
 *
 * \author Étudiant L3 Informatique
 * \date Novembre 2026
 */

/// \file tests_phase2.c
/// \brief tests de la phase 2 : GMP, blocs de 4 octets, fichiers, echange des clefs publiques
/// un test = une verification affichee ([OK] ou [KO])

#include "phase2.h"

FILE *logfp;   // utilise par les fonctions fournies

/* -------------------------------------------------------------------------- */
/*                     Compteurs et métriques de test                         */
/* -------------------------------------------------------------------------- */
static int nb_tests = 0;
static int nb_ko = 0;

/**
 * \brief Évalue une assertion et met à jour le bilan des tests.
 * \param condition Prédicat booléen (1 si succès, 0 sinon).
 * \param nom Libellé descriptif du test unitaire.
 */
static void verifier(int condition, const char *nom){
    nb_tests++;
    if (condition){
        printf("[OK] %s\n", nom);
    } else {
        printf("[KO] %s\n", nom);
        nb_ko++;
    }
}

/* -------------------------------------------------------------------------- */
/*                       Utilitaires de manipulation I/O                      */
/* -------------------------------------------------------------------------- */

/// ecrit n octets dans un fichier
static void ecrire_octets(const char *fichier, const uint8_t *octets, size_t n){
    FILE *f = fopen(fichier, "wb");
    fwrite(octets, 1, n, f);
    fclose(f);
}

/// taille d'un fichier en octets (-1 s'il n'existe pas)
static long taille_fichier(const char *fichier){
    FILE *f = fopen(fichier, "rb");
    if (f == NULL){
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long taille = ftell(f);
    fclose(f);
    return taille;
}

/// 1 si les deux fichiers ont exactement le meme contenu
static int fichiers_identiques(const char *a, const char *b){
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    int ok = 1;
    if (fa == NULL || fb == NULL){
        ok = 0;
    }
    while (ok == 1){
        int ca = fgetc(fa);
        int cb = fgetc(fb);
        if (ca != cb){
            ok = 0;
        }
        if (ca == EOF || cb == EOF){
            break;
        }
    }
    if (fa != NULL) fclose(fa);
    if (fb != NULL) fclose(fb);
    return ok;
}

/* -------------------------------------------------------------------------- */
/*                          Suites de tests unitaires                         */
/* -------------------------------------------------------------------------- */

/**
 * \brief Vérification de l'exponentiation modulaire GMP vs uint64_t.
 * \note Valide l'absence d'overflow 64 bits sur les calculs en grand modulo.
 */
static void test_gmp(void){
    printf("\n--- GMP ---\n");
    mpz_t res;
    mpz_init(res);

    // exemple du cours : clef publique (3, 33), clef privee (7, 33)
    puissance_mod_n_gmp(res, 4, 3, 33);
    verifier(mpz_get_u64(res) == 31, "4^3 mod 33 = 31");
    puissance_mod_n_gmp(res, 31, 7, 33);
    verifier(mpz_get_u64(res) == 4, "31^7 mod 33 = 4");

    // meme resultat que la version uint64 quand elle ne deborde pas (n < 2^32)
    int identiques = 1;
    for (int i = 0; i < 1000; i++){
        uint64_t n = 2 + (uint64_t)rand() % 4000000000ULL;
        uint64_t a = (uint64_t)rand() % n;
        uint64_t e = (uint64_t)rand() % 100000;
        puissance_mod_n_gmp(res, a, e, n);
        if (mpz_get_u64(res) != puissance_mod_n(a, e, n)){
            identiques = 0;
        }
    }
    verifier(identiques, "1000 calculs : meme resultat que puissance_mod_n pour n < 2^32");

    // grand modulo : (n-1)^2 = 1 mod n, alors que la version uint64 deborde
    uint64_t grand = 18446744073709551557ULL;   // plus grand premier < 2^64
    puissance_mod_n_gmp(res, grand - 1, 2, grand);
    verifier(mpz_get_u64(res) == 1, "(n-1)^2 mod n = 1 avec n proche de 2^64");
    verifier(puissance_mod_n(grand - 1, 2, grand) != 1, "la version uint64 deborde sur ce calcul (attendu)");

    // conversions uint64 <-> GMP
    mpz_set_u64(res, UINT64_MAX);
    verifier(mpz_get_u64(res) == UINT64_MAX, "mpz_set_u64 / mpz_get_u64 avec UINT64_MAX");
    mpz_set_u64(res, 0);
    verifier(mpz_get_u64(res) == 0, "mpz_set_u64 / mpz_get_u64 avec 0");

    mpz_clear(res);
}

/**
 * \brief Validation de la génération de clés RSA GMP (genKeysGMP).
 * \note Vérifie les bornes sur p et q ainsi que la composition du module N = p * q.
 */
static void test_cles(void){
    printf("\n--- clefs ---\n");
    rsaKey_t pub, priv;

    verifier(genKeysGMP(&pub, &priv, 65536) == 0, "max_prime trop petit refuse (65536)");
    verifier(genKeysGMP(&pub, &priv, MAX_PRIME_GMP + 1) == 0, "max_prime trop grand refuse (2^32)");

    int ok = 1;
    for (int i = 0; i < 20; i++){
        genKeysGMP(&pub, &priv, MAX_PRIME_GMP);
        if (pub.N <= UINT32_MAX || pub.N != priv.N){
            ok = 0;
        }
        // N doit etre le produit de deux nombres premiers : il ne doit pas etre premier lui-meme
        mpz_t n;
        mpz_init(n);
        mpz_set_u64(n, pub.N);
        if (mpz_probab_prime_p(n, 25) != 0){
            ok = 0;
        }
        mpz_clear(n);
    }
    verifier(ok, "20 paires : 2^32 < N < 2^64, meme N pour les deux clefs, N non premier");

    // plus petite borne acceptee
    verifier(genKeysGMP(&pub, &priv, MIN_PRIME_GMP) == 1 && pub.N > UINT32_MAX, "plus petite borne acceptee (70000) : N > 2^32");
}

/**
 * \brief Test du chiffrement/déchiffrement par bloc de 32 bits (4 octets).
 * \note Assure la bijection m = D(E(m)) pour tout m dans [0, 2^32 - 1].
 */
static void test_blocs(void){
    printf("\n--- blocs ---\n");
    rsaKey_t pub, priv;
    genKeysGMP(&pub, &priv, MAX_PRIME_GMP);

    verifier(dechiffrer_bloc(chiffrer_bloc(0, pub), priv) == 0, "bloc 0");
    verifier(dechiffrer_bloc(chiffrer_bloc(1, pub), priv) == 1, "bloc 1");
    verifier(dechiffrer_bloc(chiffrer_bloc(UINT32_MAX, pub), priv) == UINT32_MAX, "bloc 2^32 - 1 (le plus grand)");

    uint8_t abcd[4] = {'A', 'B', 'C', 'D'};
    uint32_t bloc = convert_4byte2int(abcd);
    verifier(dechiffrer_bloc(chiffrer_bloc(bloc, pub), priv) == bloc, "bloc \"ABCD\"");

    // 1000 blocs au hasard sur 5 paires de clefs
    int ok = 1;
    for (int p = 0; p < 5; p++){
        genKeysGMP(&pub, &priv, MAX_PRIME_GMP);
        for (int i = 0; i < 200; i++){
            uint32_t m = (uint32_t)(rand() % 65536) * 65536 + (uint32_t)(rand() % 65536);
            if (dechiffrer_bloc(chiffrer_bloc(m, pub), priv) != m){
                ok = 0;
            }
        }
    }
    verifier(ok, "1000 blocs au hasard sur 5 paires de clefs");

    // un meme octet ne donne plus toujours le meme chiffre : il depend de ses voisins
    uint8_t aaaa[4] = {'a', 'a', 'a', 'a'};
    uint8_t aaab[4] = {'a', 'a', 'a', 'b'};
    verifier(chiffrer_bloc(convert_4byte2int(aaaa), pub) != chiffrer_bloc(convert_4byte2int(aaab), pub),
             "\"aaaa\" et \"aaab\" donnent des chiffres differents");
}

/**
 * \brief Validation du pipeline fichier : padding, structure binaire et robustesse.
 * \note Structure attendue du fichier chiffré : Magic/Taille (8 octets) + N * 8 octets.
 */
static void test_fichiers(void){
    printf("\n--- fichiers ---\n");
    rsaKey_t pub, priv;
    genKeysGMP(&pub, &priv, MAX_PRIME_GMP);

    // fichiers de 0 a 9 octets : tous les cas de remplissage du dernier bloc
    int ok = 1;
    int tailles_ok = 1;
    uint8_t octets[1000];
    for (int n = 0; n <= 9; n++){
        for (int i = 0; i < n; i++){
            octets[i] = (uint8_t)(rand() % 256);
        }
        ecrire_octets("t2_clair.bin", octets, n);
        chiffrer_fichier_blocs("t2_clair.bin", "t2_chiffre.bin", pub);
        dechiffrer_fichier_blocs("t2_chiffre.bin", "t2_dechiffre.bin", priv);
        if (fichiers_identiques("t2_clair.bin", "t2_dechiffre.bin") == 0){
            ok = 0;
        }
        // en-tete de 8 octets + 8 octets par bloc de 4
        long attendu = 8 + 8 * ((n + 3) / 4);
        if (taille_fichier("t2_chiffre.bin") != attendu){
            tailles_ok = 0;
        }
    }
    verifier(ok, "fichiers de 0 a 9 octets : dechiffre = original");
    verifier(tailles_ok, "taille du chiffre = 8 + 8 x (nombre de blocs)");

    // les 256 valeurs d'octet, plusieurs fois
    for (int i = 0; i < 1000; i++){
        octets[i] = (uint8_t)(i % 256);
    }
    ecrire_octets("t2_clair.bin", octets, 1000);
    chiffrer_fichier_blocs("t2_clair.bin", "t2_chiffre.bin", pub);
    dechiffrer_fichier_blocs("t2_chiffre.bin", "t2_dechiffre.bin", priv);
    verifier(fichiers_identiques("t2_clair.bin", "t2_dechiffre.bin"), "fichier de 1000 octets (toutes les valeurs 0..255)");

    // texte UTF-8
    const char *texte = "Héllo, ça marche ? 10 € !\n";
    ecrire_octets("t2_clair.bin", (const uint8_t *)texte, strlen(texte));
    chiffrer_fichier_blocs("t2_clair.bin", "t2_chiffre.bin", pub);
    dechiffrer_fichier_blocs("t2_chiffre.bin", "t2_dechiffre.bin", priv);
    verifier(fichiers_identiques("t2_clair.bin", "t2_dechiffre.bin"), "texte UTF-8 avec accents");

    // message chiffre -> base64 -> binaire -> dechiffre (envoi par mail)
    binaire_vers_base64("t2_chiffre.bin", "t2_chiffre.b64");
    base64_vers_binaire("t2_chiffre.b64", "t2_chiffre2.bin");
    dechiffrer_fichier_blocs("t2_chiffre2.bin", "t2_dechiffre.bin", priv);
    verifier(fichiers_identiques("t2_clair.bin", "t2_dechiffre.bin"), "chiffre -> base64 -> binaire -> dechiffre");

    // mauvaise clef : le resultat est different
    rsaKey_t pub2, priv2;
    genKeysGMP(&pub2, &priv2, MAX_PRIME_GMP);
    dechiffrer_fichier_blocs("t2_chiffre.bin", "t2_dechiffre.bin", priv2);
    verifier(fichiers_identiques("t2_clair.bin", "t2_dechiffre.bin") == 0, "une autre clef ne dechiffre pas");

    // erreurs
    FILE *f = fopen("t2_chiffre.bin", "rb");
    uint8_t tout[256];
    size_t lus = fread(tout, 1, sizeof tout, f);
    fclose(f);
    ecrire_octets("t2_tronque.bin", tout, lus - 3);
    verifier(dechiffrer_fichier_blocs("t2_tronque.bin", "t2_dechiffre.bin", priv) == 0, "fichier chiffre tronque refuse");
    tout[lus] = 0;
    ecrire_octets("t2_tronque.bin", tout, lus + 1);
    verifier(dechiffrer_fichier_blocs("t2_tronque.bin", "t2_dechiffre.bin", priv) == 0, "donnees en trop refusees");
    ecrire_octets("t2_tronque.bin", tout, 5);
    verifier(dechiffrer_fichier_blocs("t2_tronque.bin", "t2_dechiffre.bin", priv) == 0, "en-tete incomplet refuse");
    verifier(chiffrer_fichier_blocs("fichier_absent.txt", "t2_chiffre.bin", pub) == 0, "fichier clair inexistant refuse");

    rsaKey_t petite = {3, 33};
    verifier(chiffrer_fichier_blocs("t2_clair.bin", "t2_chiffre.bin", petite) == 0, "clef avec N <= 2^32 refusee");

    // Nettoyage des fichiers temporaires de test
    remove("t2_clair.bin");
    remove("t2_chiffre.bin");
    remove("t2_chiffre2.bin");
    remove("t2_chiffre.b64");
    remove("t2_dechiffre.bin");
    remove("t2_tronque.bin");
}

/**
 * \brief Sérialisation et désérialisation de clés publiques en Base64 et fichiers.
 */
static void test_echange_cles(void){
    printf("\n--- echange des clefs publiques ---\n");
    rsaKey_t pub, priv, relue;
    genKeysGMP(&pub, &priv, MAX_PRIME_GMP);

    char texte[64];
    verifier(cle_vers_base64(pub, texte, sizeof texte) == 1 && strlen(texte) == 24, "clef -> base64 de 24 caracteres");
    verifier(base64_vers_cle(texte, &relue) == 1 && relue.E == pub.E && relue.N == pub.N, "base64 -> clef identique");

    char petit[10];
    verifier(cle_vers_base64(pub, petit, sizeof petit) == 0, "tableau trop petit refuse");
    verifier(base64_vers_cle("SGkh", &relue) == 0, "texte base64 trop court refuse");

    verifier(sauver_cle_publique(pub, "t2_pub.txt") == 1, "sauvegarde de la clef publique dans un fichier");
    relue.E = 0;
    relue.N = 0;
    verifier(charger_cle_publique("t2_pub.txt", &relue) == 1 && relue.E == pub.E && relue.N == pub.N,
             "chargement : clef identique");

    ecrire_octets("t2_pub.txt", (const uint8_t *)"n'importe quoi\n", 15);
    verifier(charger_cle_publique("t2_pub.txt", &relue) == 0, "fichier qui n'est pas une clef refuse");
    verifier(charger_cle_publique("fichier_absent.txt", &relue) == 0, "fichier de clef inexistant refuse");
    remove("t2_pub.txt");
}

/* -------------------------------------------------------------------------- */
/*                                Point d'entrée                              */
/* -------------------------------------------------------------------------- */

int main(void){
    srand((unsigned)time(NULL));
    logfp = stderr;

    printf("===== TESTS PHASE 2 =====\n");
    test_gmp();
    test_cles();
    test_blocs();
    test_fichiers();
    test_echange_cles();

    // Bilan final d'exécution
    if (nb_ko == 0){
        printf("\n===== TOUT EST OK (%d tests) =====\n", nb_tests);
    } else {
        printf("\n===== ECHEC : %d test(s) sur %d en echec =====\n", nb_ko, nb_tests);
    }
    base64_cleanup();
    return nb_ko != 0;
}