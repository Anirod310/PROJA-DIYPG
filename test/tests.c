/// \file tests.c
/// \brief tests simples de la phase 1 : un test = une verification affichee [OK] ou [KO]
#include "phase1.h"

static int nb_ko = 0;

// affiche le resultat d'un test
static void verifier(int condition, const char *nom){
    if (condition) printf("[OK] %s\n", nom);
    else { printf("[KO] %s\n", nom); nb_ko++; }
}

// ecrit un petit texte dans un fichier
static void ecrire_texte(const char *fichier, const char *texte){
    FILE *f = fopen(fichier, "wb");
    fwrite(texte, 1, strlen(texte), f);
    fclose(f);
}

// lit un fichier dans buf (taille max n-1) et le termine par \0
static void lire_texte(const char *fichier, char *buf, size_t n){
    FILE *f = fopen(fichier, "rb");
    size_t lu = 0;
    if (f) { lu = fread(buf, 1, n - 1, f); fclose(f); }
    buf[lu] = '\0';
}

/* ---------- maths ---------- */
static void test_maths(void){
    printf("\n--- maths ---\n");
    verifier(premier(7) == 1,  "7 est premier");
    verifier(premier(8) == 0,  "8 n'est pas premier");
    verifier(premier(1) == 0,  "1 n'est pas premier");
    verifier(pgcdFast(12, 18) == 6, "pgcd(12,18) = 6");
    verifier(puissance_mod_n(4, 3, 33) == 31, "4^3 mod 33 = 31 (exemple du sujet)");
    verifier(puissance_mod_n(31, 7, 33) == 4, "31^7 mod 33 = 4 (exemple du sujet)");

    int64_t u, v;
    int64_t r = bezout(240, 46, &u, &v);
    verifier(r == 2, "bezout(240,46) : pgcd = 2");
    verifier(240 * u + 46 * v == 2, "bezout(240,46) : 240*u + 46*v = 2");
}

/* ---------- clefs ---------- */
static void test_cles(void){
    printf("\n--- clefs ---\n");
    keyPair_t kp, kp2;
    genKeysRabin(&kp.pubKey, &kp.privKey, MAX_PRIME);

    verifier(kp.pubKey.N == kp.privKey.N, "les deux clefs ont le meme N");
    verifier(saveKeytoFile(kp, "test_keys.bin") == 1, "sauvegarde des clefs");
    verifier(loadKeytoprog(&kp2, "test_keys.bin") == 1, "chargement des clefs");
    verifier(kp.pubKey.E == kp2.pubKey.E && kp.pubKey.N == kp2.pubKey.N
          && kp.privKey.E == kp2.privKey.E && kp.privKey.N == kp2.privKey.N,
             "clefs rechargees = clefs sauvegardees");
    remove("test_keys.bin");
}

/* ---------- chiffrement d'octets ---------- */
static void test_octets(void){
    printf("\n--- chiffrement d'octets ---\n");
    keyPair_t kp;
    genKeysRabin(&kp.pubKey, &kp.privKey, MAX_PRIME);

    // un seul caractere
    uint8_t clair1[1] = { 'A' };
    uint8_t chiffre1[8];
    uint8_t resultat1[1];
    chiffrer_octets(clair1, 1, kp.pubKey, chiffre1);
    dechiffrer_octets(chiffre1, 8, kp.privKey, resultat1);
    verifier(resultat1[0] == 'A', "chiffrer puis dechiffrer 'A'");

    // une chaine
    const char *texte = "Bonjour";
    size_t n = strlen(texte);
    uint8_t chiffre[8 * 16];
    uint8_t resultat[16];
    chiffrer_octets((const uint8_t *)texte, n, kp.pubKey, chiffre);
    dechiffrer_octets(chiffre, 8 * n, kp.privKey, resultat);
    resultat[n] = '\0';
    verifier(strcmp((char *)resultat, texte) == 0, "chiffrer puis dechiffrer \"Bonjour\"");

    // la taille du chiffre
    verifier(chiffrer_octets((const uint8_t *)texte, n, kp.pubKey, chiffre) == 8 * n,
             "le chiffre fait 8 octets par octet clair");
}

/* ---------- fichiers ---------- */
static void test_fichiers(void){
    printf("\n--- fichiers ---\n");
    keyPair_t kp;
    genKeysRabin(&kp.pubKey, &kp.privKey, MAX_PRIME);

    const char *texte = "Ceci est un test de fichier.";
    char relu[100];

    ecrire_texte("t_clair.txt", texte);
    verifier(chiffrer_fichier("t_clair.txt", "t_chiffre.bin", kp.pubKey) == 1, "chiffrement du fichier");
    verifier(dechiffrer_fichier("t_chiffre.bin", "t_dechiffre.txt", kp.privKey) == 1, "dechiffrement du fichier");

    lire_texte("t_dechiffre.txt", relu, sizeof relu);
    verifier(strcmp(relu, texte) == 0, "le fichier dechiffre est identique a l'original");

    remove("t_clair.txt");
    remove("t_chiffre.bin");
    remove("t_dechiffre.txt");
}

/* ---------- base64 ---------- */
static void test_base64(void){
    printf("\n--- base64 ---\n");
    size_t taille;

    // encodage
    char *e = base64_encode((const unsigned char *)"Hi!", 3, &taille);
    verifier(e != NULL && strcmp(e, "SGkh") == 0, "\"Hi!\" -> \"SGkh\"");
    free(e);

    e = base64_encode((const unsigned char *)"f", 1, &taille);
    verifier(e != NULL && strcmp(e, "Zg==") == 0, "\"f\" -> \"Zg==\" (avec padding)");
    free(e);

    // decodage
    unsigned char *d = base64_decode("SGkh", 4, &taille);
    verifier(d != NULL && taille == 3 && memcmp(d, "Hi!", 3) == 0, "\"SGkh\" -> \"Hi!\"");
    free(d);

    // un entier 32 bits
    uint32_t nombre = 0xDEADBEEF;
    uint8_t octets[4];
    convertInt2uchar(nombre, octets);
    e = base64_encode(octets, 4, &taille);
    d = base64_decode(e, taille, &taille);
    verifier(d != NULL && convert_4byte2int(d) == nombre, "uint32 -> base64 -> uint32");
    free(e);
    free(d);

    // un fichier
    ecrire_texte("t_b64_src.txt", "Hi!");
    fichier_vers_base64("t_b64_src.txt", "t_b64.b64");
    char relu[100];
    lire_texte("t_b64.b64", relu, sizeof relu);
    verifier(strcmp(relu, "SGkh") == 0, "fichier -> fichier base64 (\"SGkh\")");

    base64_vers_fichier("t_b64.b64", "t_b64_dst.txt");
    lire_texte("t_b64_dst.txt", relu, sizeof relu);
    verifier(strcmp(relu, "Hi!") == 0, "fichier base64 -> fichier (\"Hi!\")");

    remove("t_b64_src.txt");
    remove("t_b64.b64");
    remove("t_b64_dst.txt");
    base64_cleanup();
}

/* ---------- lancement ---------- */
int lancer_tous_les_tests(uint64_t max_prime){
    (void)max_prime;   // les tests utilisent MAX_PRIME du header
    nb_ko = 0;
    printf("===== TESTS PHASE 1 =====\n");
    test_maths();
    test_cles();
    test_octets();
    test_fichiers();
    test_base64();
    printf("\n===== %s (%d test(s) en echec) =====\n", nb_ko == 0 ? "TOUT EST OK" : "ECHEC", nb_ko);
    return nb_ko;
}