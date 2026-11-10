/// \file tests_conversions.c
/// \brief tests des conversions base64, de l'echange des clefs publiques
/// et des commandes bin-2b64 / b64-2bin de l'interprete
/// un test = une verification affichee ([OK] ou [KO])

#include "conversions.h"

FILE *logfp;   // utilise par les fonctions fournies

static int nb_tests = 0;
static int nb_ko = 0;

static void verifier(int condition, const char *nom){
    nb_tests++;
    if (condition){
        printf("[OK] %s\n", nom);
    } else {
        printf("[KO] %s\n", nom);
        nb_ko++;
    }
}

static void ecrire_octets(const char *fichier, const void *octets, size_t n){
    FILE *f = fopen(fichier, "wb");
    fwrite(octets, 1, n, f);
    fclose(f);
}

static void ecrire_texte(const char *fichier, const char *texte){
    ecrire_octets(fichier, texte, strlen(texte));
}

/// lit un fichier texte dans buf (termine par '\0')
static void lire_texte(const char *fichier, char *buf, size_t n){
    FILE *f = fopen(fichier, "rb");
    size_t lu = 0;
    if (f != NULL){
        lu = fread(buf, 1, n - 1, f);
        fclose(f);
    }
    buf[lu] = '\0';
}

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

/// verifie que toutes les lignes d'un fichier base64 font 76 caracteres, sauf la derniere
static int lignes_de_76(const char *fichier){
    char texte[20000];
    lire_texte(fichier, texte, sizeof texte);
    char *ligne = strtok(texte, "\n");
    int ok = 1;
    while (ligne != NULL){
        char *suivante = strtok(NULL, "\n");
        size_t lg = strlen(ligne);
        if (suivante != NULL && lg != LARGEUR_LIGNE_B64){
            ok = 0;                      // une ligne du milieu doit faire 76 caracteres
        }
        if (suivante == NULL && (lg == 0 || lg > LARGEUR_LIGNE_B64)){
            ok = 0;                      // la derniere fait entre 1 et 76 caracteres
        }
        ligne = suivante;
    }
    return ok;
}

static void test_texte_base64(void){
    printf("\n--- texte base64 ---\n");
    char texte[64];

    strcpy(texte, " SG\tk h\r\n");
    verifier(enlever_espaces(texte, strlen(texte)) == 4 && strcmp(texte, "SGkh") == 0, "enlever_espaces : \" SG\\tk h\\r\\n\" -> \"SGkh\"");

    verifier(base64_valide("SGkh", 4) == 1, "\"SGkh\" valide");
    verifier(base64_valide("SGk=", 4) == 1, "\"SGk=\" valide (1 =)");
    verifier(base64_valide("Zg==", 4) == 1, "\"Zg==\" valide (2 =)");
    verifier(base64_valide("", 0) == 1, "texte vide valide");
    verifier(base64_valide("SGk", 3) == 0, "longueur non multiple de 4 refusee");
    verifier(base64_valide("SGk#", 4) == 0, "caractere '#' refuse");
    verifier(base64_valide("S=kh", 4) == 0, "'=' au milieu refuse");
    verifier(base64_valide("====", 4) == 0, "\"====\" refuse (3 ou 4 '=')");
}

static void test_fichiers(void){
    printf("\n--- fichiers binaire <-> base64 ---\n");
    char texte[20000];

    // meme resultat que la commande du sujet : echo -n 'Hi!' | base64
    ecrire_texte("tc_bin", "Hi!");
    verifier(binaire_vers_base64("tc_bin", "tc_b64") == 1, "binaire_vers_base64 (\"Hi!\")");
    lire_texte("tc_b64", texte, sizeof texte);
    verifier(strcmp(texte, "SGkh\n") == 0, "\"Hi!\" -> \"SGkh\" comme la commande base64");

    // 57 octets -> exactement une ligne de 76 caracteres ; 114 octets -> deux lignes
    uint8_t octets[1024];
    for (int i = 0; i < 1024; i++){
        octets[i] = (uint8_t)(i % 256);
    }
    ecrire_octets("tc_bin", octets, 57);
    binaire_vers_base64("tc_bin", "tc_b64");
    verifier(taille_fichier("tc_b64") == 77, "57 octets -> une ligne de 76 caracteres");
    ecrire_octets("tc_bin", octets, 114);
    binaire_vers_base64("tc_bin", "tc_b64");
    verifier(taille_fichier("tc_b64") == 2 * 77, "114 octets -> deux lignes de 76 caracteres");

    // les 256 valeurs d'octet, 4 fois
    ecrire_octets("tc_bin", octets, 1024);
    binaire_vers_base64("tc_bin", "tc_b64");
    verifier(lignes_de_76("tc_b64"), "1024 octets : lignes de 76 caracteres, la derniere plus courte");
    verifier(base64_vers_binaire("tc_b64", "tc_bin2") == 1 && fichiers_identiques("tc_bin", "tc_bin2"),
             "1024 octets (toutes les valeurs) : binaire -> base64 -> binaire identique");

    // fichier vide
    ecrire_octets("tc_bin", "", 0);
    verifier(binaire_vers_base64("tc_bin", "tc_b64") == 1 && taille_fichier("tc_b64") == 0, "fichier vide -> base64 vide");
    verifier(base64_vers_binaire("tc_b64", "tc_bin2") == 1 && taille_fichier("tc_bin2") == 0, "base64 vide -> fichier vide");

    // texte copie depuis un mail : retours a la ligne Windows, espaces, lignes coupees ailleurs
    ecrire_texte("tc_b64", "  SGVs\r\nbG8g\r\n  ZOlk\r\n\r\n");
    verifier(base64_vers_binaire("tc_b64", "tc_bin2") == 1, "base64 avec \\r\\n, espaces et lignes vides accepte");
    lire_texte("tc_bin2", texte, sizeof texte);
    verifier(taille_fichier("tc_bin2") == 9 && memcmp(texte, "Hello d\xe9" "d", 9) == 0, "contenu decode correct (9 octets)");

    // erreurs
    ecrire_texte("tc_b64", "SGk#\n");
    verifier(base64_vers_binaire("tc_b64", "tc_bin2") == 0, "caractere invalide refuse");
    ecrire_texte("tc_b64", "SGkhS\n");
    verifier(base64_vers_binaire("tc_b64", "tc_bin2") == 0, "longueur incorrecte refusee");
    verifier(base64_vers_binaire("fichier_absent.b64", "tc_bin2") == 0, "fichier base64 absent refuse");
    verifier(binaire_vers_base64("fichier_absent.bin", "tc_b64") == 0, "fichier binaire absent refuse");

    remove("tc_bin");
    remove("tc_bin2");
    remove("tc_b64");
}

static void test_cles(void){
    printf("\n--- echange des clefs publiques ---\n");
    // clef avec de grands nombres (comme en phase 2, N proche de 2^64)
    rsaKey_t pub = {65537, 0xF3A1C2D4E5B60789ULL};
    rsaKey_t relue;

    char texte[TAILLE_CLE_B64];
    verifier(cle_vers_base64(pub, texte, sizeof texte) == 1 && strlen(texte) == 24, "clef -> base64 de 24 caracteres");
    verifier(base64_vers_cle(texte, &relue) == 1 && relue.E == pub.E && relue.N == pub.N, "base64 -> clef identique");

    char avec_espaces[64];
    snprintf(avec_espaces, sizeof avec_espaces, " %.12s\r\n%s \n", texte, texte + 12);
    verifier(base64_vers_cle(avec_espaces, &relue) == 1 && relue.N == pub.N, "clef coupee en deux lignes acceptee");

    char petit[10];
    verifier(cle_vers_base64(pub, petit, sizeof petit) == 0, "tableau trop petit refuse");
    verifier(base64_vers_cle("SGkh", &relue) == 0, "texte trop court refuse");
    verifier(base64_vers_cle("AQAB#AAAAABBkb4qjh68Cg==", &relue) == 0, "caractere invalide refuse");

    // empreinte
    char e1[TAILLE_EMPREINTE];
    char e2[TAILLE_EMPREINTE];
    empreinte_cle(pub, e1);
    empreinte_cle(pub, e2);
    verifier(strlen(e1) == 16 && strcmp(e1, e2) == 0, "empreinte : 16 caracteres, toujours la meme pour une clef");
    rsaKey_t autre = pub;
    autre.N = autre.N + 2;
    empreinte_cle(autre, e2);
    verifier(strcmp(e1, e2) != 0, "deux clefs differentes ont des empreintes differentes");

    // fichier de clef
    verifier(sauver_cle_publique(pub, "tc_pub.txt") == 1, "sauvegarde de la clef publique");
    relue.E = 0;
    relue.N = 0;
    verifier(charger_cle_publique("tc_pub.txt", &relue) == 1 && relue.E == pub.E && relue.N == pub.N, "chargement : clef identique");

    // fichier copie depuis un mail : lignes en plus, citation "> ", fins de ligne Windows
    char lu[256];
    char mail[512];
    lire_texte("tc_pub.txt", lu, sizeof lu);
    char *l2 = strchr(lu, '\n') + 1;            // ligne "cle : ..."
    char *l3 = strchr(l2, '\n') + 1;            // ligne "empreinte : ..."
    *(l2 - 1) = '\0';
    *(l3 - 1) = '\0';
    l3[strcspn(l3, "\n")] = '\0';
    snprintf(mail, sizeof mail, "Salut, voici ma clef :\r\n\r\n> %s\r\n> %s\r\n> %s\r\n\r\nA plus\r\n", lu, l2, l3);
    ecrire_texte("tc_pub.txt", mail);
    verifier(charger_cle_publique("tc_pub.txt", &relue) == 1 && relue.N == pub.N, "clef copiee dans un mail (citation, \\r\\n) acceptee");

    // clef abimee : un caractere change -> l'empreinte ne correspond plus
    char *p = strstr(mail, "cle : ") + 6;
    if (*p == 'A'){
        *p = 'B';
    } else {
        *p = 'A';
    }
    ecrire_texte("tc_pub.txt", mail);
    verifier(charger_cle_publique("tc_pub.txt", &relue) == 0, "clef modifiee refusee (empreinte incorrecte)");

    ecrire_texte("tc_pub.txt", "cle : AQABAAAAAABBkb4qjh68Cg==\n");
    verifier(charger_cle_publique("tc_pub.txt", &relue) == 0, "fichier sans en-tete ni empreinte refuse");
    verifier(charger_cle_publique("fichier_absent.txt", &relue) == 0, "fichier de clef absent refuse");

    // plusieurs clefs au hasard (generees avec la phase 1) : aller-retour par fichier
    int ok = 1;
    for (int i = 0; i < 20; i++){
        keyPair_t kp;
        genKeysSures(&kp.pubKey, &kp.privKey, MAX_PRIME);
        sauver_cle_publique(kp.pubKey, "tc_pub.txt");
        if (charger_cle_publique("tc_pub.txt", &relue) == 0 || relue.E != kp.pubKey.E || relue.N != kp.pubKey.N){
            ok = 0;
        }
    }
    verifier(ok, "20 clefs au hasard : fichier de clef -> clef identique");
    remove("tc_pub.txt");
}

static void test_echange_complet(void){
    printf("\n--- echange complet entre deux personnes ---\n");
    // le chiffrement utilise ici est celui de la phase 1 : les conversions marchent pareil
    // avec le chiffrement par blocs de la phase 2 (ce sont des fichiers binaires comme les autres)

    // Alice cree ses clefs et envoie sa clef publique
    keyPair_t alice;
    rsaKey_t pub_recue;
    genKeysSures(&alice.pubKey, &alice.privKey, MAX_PRIME);
    sauver_cle_publique(alice.pubKey, "tc_alice_pub.txt");

    // Bob charge la clef, chiffre un message et le convertit en base64 pour le mail
    verifier(charger_cle_publique("tc_alice_pub.txt", &pub_recue) == 1, "Bob charge la clef publique d'Alice");
    ecrire_texte("tc_message.txt", "Rendez-vous demain a 14h devant la BU. Ça te va ? 5 €\n");
    verifier(chiffrer_fichier("tc_message.txt", "tc_message.rsa", pub_recue) == 1, "Bob chiffre le message");
    verifier(binaire_vers_base64("tc_message.rsa", "tc_message.b64") == 1, "Bob convertit le chiffre en base64");
    verifier(lignes_de_76("tc_message.b64"), "le base64 est en lignes de 76 caracteres (format des mails)");

    // Alice recoit le base64, le reconvertit et dechiffre avec sa clef privee
    verifier(base64_vers_binaire("tc_message.b64", "tc_recu.rsa") == 1, "Alice reconvertit le base64 en binaire");
    verifier(fichiers_identiques("tc_message.rsa", "tc_recu.rsa"), "le chiffre recu est identique au chiffre envoye");
    verifier(dechiffrer_fichier("tc_recu.rsa", "tc_recu.txt", alice.privKey) == 1
             && fichiers_identiques("tc_message.txt", "tc_recu.txt"), "Alice retrouve le message de Bob");

    remove("tc_alice_pub.txt");
    remove("tc_message.txt");
    remove("tc_message.rsa");
    remove("tc_message.b64");
    remove("tc_recu.rsa");
    remove("tc_recu.txt");
}

static void test_commandes(void){
    printf("\n--- commandes bin-2b64 et b64-2bin ---\n");
    uint8_t octets[300];
    for (int i = 0; i < 300; i++){
        octets[i] = (uint8_t)((i * 7) % 256);
    }
    ecrire_octets("tc_bin", octets, 300);

    char *cmd1[] = {"bin-2b64", "tc_bin", "tc_b64"};
    char *cmd2[] = {"b64-2bin", "tc_b64", "tc_bin2"};
    verifier(commande_bin_2b64(3, cmd1) == 1, "bin-2b64 tc_bin tc_b64");
    verifier(commande_b64_2bin(3, cmd2) == 1, "b64-2bin tc_b64 tc_bin2");
    verifier(fichiers_identiques("tc_bin", "tc_bin2"), "fichier identique apres les deux commandes");

    char *trop_court[] = {"bin-2b64", "tc_bin"};
    verifier(commande_bin_2b64(2, trop_court) == 0, "bin-2b64 sans fichier de sortie refuse");
    char *trop_long[] = {"b64-2bin", "a", "b", "c"};
    verifier(commande_b64_2bin(4, trop_long) == 0, "b64-2bin avec trop d'arguments refuse");

    char *absent[] = {"bin-2b64", "fichier_absent.bin", "tc_b64"};
    verifier(commande_bin_2b64(3, absent) == 0, "bin-2b64 sur un fichier absent refuse");
    ecrire_texte("tc_b64", "ceci n'est pas du base64 !\n");
    verifier(commande_b64_2bin(3, cmd2) == 0, "b64-2bin sur un texte qui n'est pas du base64 refuse");

    remove("tc_bin");
    remove("tc_bin2");
    remove("tc_b64");
}

int main(void){
    srand((unsigned)time(NULL));
    logfp = stderr;

    printf("===== TESTS BASE64, ECHANGE DES CLEFS ET COMMANDES =====\n");
    test_texte_base64();
    test_fichiers();
    test_cles();
    test_echange_complet();
    test_commandes();

    if (nb_ko == 0){
        printf("\n===== TOUT EST OK (%d tests) =====\n", nb_tests);
    } else {
        printf("\n===== ECHEC : %d test(s) sur %d en echec =====\n", nb_ko, nb_tests);
    }
    base64_cleanup();
    return nb_ko != 0;
}
