/**
 * \file tests_phase3.c
 * \brief Banc de tests unitaires et d'intégration pour la Phase 3 (REPL & Trousseau).
 * \details Validation de l'interpréteur de commandes (V1.1 et V2), de la gestion des
 *          contacts et métadonnées, du chiffrement symétrique du trousseau et de
 *          la conformité des permissions POSIX (chmod 0600).
 *
 * \author Étudiant L3 Informatique
 * \date Novembre 2026
 */

/// \file tests_phase3.c
/// \brief tests de la phase 3 : commandes de l'interprete (V1.1 et V2) et sauvegarde chiffree
/// un test = une verification affichee ([OK] ou [KO])

#include <sys/stat.h>
#include "interprete.h"

FILE *logfp;   // utilise par les fonctions fournies

/* -------------------------------------------------------------------------- */
/*                     Compteurs et métriques de test                         */
/* -------------------------------------------------------------------------- */
static int nb_tests = 0;
static int nb_ko = 0;

/**
 * \brief Évalue une assertion et met à jour le bilan d'exécution.
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
/*                       Harnais d'exécution du REPL                          */
/* -------------------------------------------------------------------------- */

/// execute une commande de l'interprete
/// \param reponses : ce que l'utilisateur taperait dans les menus (mot de passe, nom...), "" si rien
static int cmd(trousseau_t *t, const char *commande, const char *reponses){
    char ligne[512];
    strncpy(ligne, commande, sizeof ligne - 1);
    ligne[sizeof ligne - 1] = '\0';

    // les reponses sont mises dans un fichier temporaire, lu a la place du clavier
    FILE *entree = tmpfile();
    fputs(reponses, entree);
    rewind(entree);

    printf("> %s\n", commande);
    int code = executer_commande(t, ligne, entree);
    fclose(entree);
    return code;
}

/* -------------------------------------------------------------------------- */
/*                       Utilitaires système et fichiers                      */
/* -------------------------------------------------------------------------- */

static void ecrire_texte(const char *fichier, const char *texte){
    FILE *f = fopen(fichier, "wb");
    fwrite(texte, 1, strlen(texte), f);
    fclose(f);
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

/// 1 si le fichier contient le texte
static int fichier_contient(const char *fichier, const char *texte){
    FILE *f = fopen(fichier, "rb");
    if (f == NULL){
        return 0;
    }
    size_t lg = strlen(texte);
    char *contenu = malloc(200000);
    size_t lus = fread(contenu, 1, 200000, f);
    fclose(f);
    int trouve = 0;
    for (size_t i = 0; i + lg <= lus; i++){
        if (memcmp(contenu + i, texte, lg) == 0){
            trouve = 1;
        }
    }
    free(contenu);
    return trouve;
}

/* -------------------------------------------------------------------------- */
/*                          Suites de tests fonctionnels                      */
/* -------------------------------------------------------------------------- */

/**
 * \brief Validation des commandes de gestion de clés (V1.1).
 * \details Couvre l'unicité des alias, le parsing des arguments et l'affichage.
 */
static void test_cles(trousseau_t *t){
    printf("\n--- V1.1 : clefs ---\n");
    verifier(cmd(t, "newkeys moi crypt", "") == COMMANDE_OK, "newkeys moi crypt");
    verifier(cmd(t, "newkeys signature sign", "") == COMMANDE_OK, "newkeys signature sign");
    verifier(t->nb_cles == 2, "2 clefs dans le trousseau");
    verifier(cmd(t, "newkeys moi crypt", "") == COMMANDE_ERREUR, "identificateur deja utilise refuse");
    verifier(cmd(t, "newkeys autre bidon", "") == COMMANDE_ERREUR, "type inconnu refuse");
    verifier(cmd(t, "newkeys a/b crypt", "") == COMMANDE_ERREUR, "identificateur avec '/' refuse");
    verifier(cmd(t, "newkeys moi", "") == COMMANDE_ERREUR, "nombre d'arguments incorrect refuse");

    verifier(cmd(t, "listkeys", "") == COMMANDE_OK, "listkeys");
    verifier(cmd(t, "listkeys moi", "") == COMMANDE_OK, "listkeys moi");
    verifier(cmd(t, "listkeys inconnue", "") == COMMANDE_ERREUR, "listkeys sur une clef inconnue");

    verifier(cmd(t, "show moi", "") == COMMANDE_OK, "show moi (les deux clefs)");
    verifier(cmd(t, "show moi pub", "") == COMMANDE_OK, "show moi pub");
    verifier(cmd(t, "show moi bidon", "") == COMMANDE_ERREUR, "show avec une option inconnue");
}

/**
 * \brief Validation des pipelines de chiffrement/déchiffrement et conversions.
 * \details Vérifie le filtrage selon le type d'usage ('crypt' vs 'sign').
 */
static void test_chiffrement(trousseau_t *t){
    printf("\n--- V1.1 : chiffrement ---\n");
    ecrire_texte("t3_clair.txt", "Message secret pour la phase 3, avec des accents : é à ç €\n");

    verifier(cmd(t, "crypt t3_clair.txt t3_chiffre.bin moi", "") == COMMANDE_OK, "crypt avec moi");
    verifier(cmd(t, "uncrypt t3_chiffre.bin t3_dechiffre.txt moi", "") == COMMANDE_OK, "uncrypt avec moi");
    verifier(fichiers_identiques("t3_clair.txt", "t3_dechiffre.txt"), "fichier dechiffre = original");

    verifier(cmd(t, "crypt t3_clair.txt t3_chiffre.bin signature", "") == COMMANDE_ERREUR, "crypt avec une clef de type sign refuse");
    verifier(cmd(t, "uncrypt t3_chiffre.bin t3_dechiffre.txt signature", "") == COMMANDE_ERREUR, "uncrypt avec une clef de type sign refuse");
    verifier(cmd(t, "crypt t3_clair.txt t3_chiffre.bin inconnue", "") == COMMANDE_ERREUR, "crypt avec une clef inconnue refuse");

    verifier(cmd(t, "bin-2b64 t3_chiffre.bin t3_chiffre.b64", "") == COMMANDE_OK, "bin-2b64");
    verifier(cmd(t, "b64-2bin t3_chiffre.b64 t3_chiffre2.bin", "") == COMMANDE_OK, "b64-2bin");
    verifier(fichiers_identiques("t3_chiffre.bin", "t3_chiffre2.bin"), "binaire -> base64 -> binaire identique");

    verifier(cmd(t, "savepub moi t3_pub.txt", "") == COMMANDE_OK, "savepub moi");
    verifier(cmd(t, "savepub inconnue t3_pub2.txt", "") == COMMANDE_ERREUR, "savepub sur une clef inconnue");
}

/**
 * \brief Validation de l'annuaire de contacts et des clés publiques distantes (V2).
 * \details Gestion des clés multiples par contact et résolution des ambiguïtés.
 */
static void test_contacts(trousseau_t *t){
    printf("\n--- V2 : contacts ---\n");
    verifier(cmd(t, "addcontact alice", "Durand\nAlice\nvoisine\n") == COMMANDE_OK, "addcontact alice");
    verifier(t->nb_contacts == 1 && strcmp(t->contacts[0].nom, "Durand") == 0
             && strcmp(t->contacts[0].prenom, "Alice") == 0, "nom et prenom enregistres");
    verifier(cmd(t, "addcontact alice", "") == COMMANDE_ERREUR, "contact deja existant refuse");

    // on donne a alice notre propre clef publique : on pourra verifier le dechiffrement avec "moi"
    verifier(cmd(t, "addkeys alice", "perso\ncrypt\nt3_pub.txt\n") == COMMANDE_OK, "addkeys alice (par identificateur)");
    verifier(cmd(t, "addkeys Durand", "boulot\ncrypt\nt3_pub.txt\n") == COMMANDE_OK, "addkeys Durand (par nom)");
    verifier(t->contacts[0].nb_cles == 2, "alice a 2 clefs");
    verifier(cmd(t, "addkeys alice", "perso\ncrypt\nt3_pub.txt\n") == COMMANDE_ERREUR, "clef deja existante refusee");
    verifier(cmd(t, "addkeys alice", "autre\ncrypt\nfichier_absent.txt\n") == COMMANDE_ERREUR, "fichier de clef absent refuse");

    verifier(cmd(t, "crypt t3_clair.txt t3_chiffre.bin alice", "") == COMMANDE_ERREUR, "crypt alice refuse : 2 clefs crypt, il faut preciser");
    verifier(cmd(t, "crypt t3_clair.txt t3_chiffre.bin alice/perso", "") == COMMANDE_OK, "crypt avec alice/perso");
    cmd(t, "uncrypt t3_chiffre.bin t3_dechiffre.txt moi", "");
    verifier(fichiers_identiques("t3_clair.txt", "t3_dechiffre.txt"), "le message chiffre pour alice/perso se dechiffre (meme clef que moi)");
    verifier(cmd(t, "uncrypt t3_chiffre.bin t3_dechiffre.txt alice/perso", "") == COMMANDE_ERREUR, "uncrypt avec une clef de contact refuse (pas de clef privee)");

    verifier(cmd(t, "show alice/perso", "") == COMMANDE_OK, "show alice/perso");
    verifier(cmd(t, "show alice/inconnue", "") == COMMANDE_ERREUR, "show sur une clef de contact inconnue");

    verifier(cmd(t, "modifycontact alice", "3\ncollegue\n0\n") == COMMANDE_OK
             && strcmp(t->contacts[0].commentaire, "collegue") == 0, "modifycontact : commentaire modifie");

    verifier(cmd(t, "listcontacts", "") == COMMANDE_OK, "listcontacts");
    verifier(cmd(t, "listcontacts Durand", "") == COMMANDE_OK, "listcontacts Durand (par nom)");
    verifier(cmd(t, "listcontacts personne", "") == COMMANDE_ERREUR, "listcontacts sur un contact inconnu");

    verifier(cmd(t, "rmkeys alice/boulot", "") == COMMANDE_OK && t->contacts[0].nb_cles == 1, "rmkeys alice/boulot : seule cette clef est supprimee");
    verifier(cmd(t, "crypt t3_clair.txt t3_chiffre.bin alice", "") == COMMANDE_OK, "crypt alice : une seule clef crypt, plus besoin de preciser");
}

/**
 * \brief Validation de la persistance sécurisée du trousseau (.diypg).
 * \details Vérifie la confidentialité au repos, le mot de passe et le masque POSIX 0600.
 */
static void test_sauvegarde(trousseau_t *t){
    printf("\n--- sauvegarde ---\n");
    rsaKey_t pub_moi = t->cles[0].cles.pubKey;
    int nb_cles = t->nb_cles;

    verifier(cmd(t, "save t3_trousseau.diypg", "motdepasse\n") == COMMANDE_OK, "save avec mot de passe");
    verifier(fichier_contient("t3_trousseau.diypg", "Durand") == 0, "le fichier sauvegarde est chiffre (\"Durand\" illisible)");

    struct stat st;
    stat("t3_trousseau.diypg", &st);
    verifier((st.st_mode & 0777) == 0600, "droits du fichier : lecture/ecriture pour le proprietaire seulement");

    // on modifie le trousseau puis on recharge
    cmd(t, "rmcontact alice", "");
    cmd(t, "rmkeys moi", "");
    verifier(t->nb_contacts == 0 && t->nb_cles == nb_cles - 1, "rmcontact alice et rmkeys moi");

    verifier(cmd(t, "load t3_trousseau.diypg", "mauvais\n") == COMMANDE_ERREUR, "load avec un mauvais mot de passe refuse");
    verifier(t->nb_contacts == 0, "le trousseau n'est pas modifie apres un mauvais mot de passe");

    verifier(cmd(t, "load t3_trousseau.diypg", "motdepasse\n") == COMMANDE_OK, "load avec le bon mot de passe");
    verifier(t->nb_cles == nb_cles && t->nb_contacts == 1, "clefs et contacts retrouves");
    verifier(t->cles[0].cles.pubKey.N == pub_moi.N && strcmp(t->contacts[0].commentaire, "collegue") == 0,
             "contenu identique a la sauvegarde");

    verifier(cmd(t, "load fichier_absent.diypg", "motdepasse\n") == COMMANDE_ERREUR, "load d'un fichier absent refuse");
    ecrire_texte("t3_faux.diypg", "pas une sauvegarde");
    verifier(cmd(t, "load t3_faux.diypg", "motdepasse\n") == COMMANDE_ERREUR, "load d'un fichier qui n'est pas une sauvegarde refuse");
    verifier(cmd(t, "save t3_trousseau.diypg", "\n") == COMMANDE_ERREUR, "mot de passe vide refuse");
}

/**
 * \brief Validation des cas limites du parser CLI (entrées vides, aide, sortie).
 */
static void test_divers(trousseau_t *t){
    printf("\n--- divers ---\n");
    verifier(cmd(t, "", "") == COMMANDE_OK, "ligne vide ignoree");
    verifier(cmd(t, "bidon", "") == COMMANDE_ERREUR, "commande inconnue");
    verifier(cmd(t, "help", "") == COMMANDE_OK, "help");
    verifier(cmd(t, "quit", "") == COMMANDE_QUITTER, "quit");
}

/* -------------------------------------------------------------------------- */
/*                                Point d'entrée                              */
/* -------------------------------------------------------------------------- */

int main(void){
    srand((unsigned)time(NULL));
    logfp = stderr;

    static trousseau_t t;
    init_trousseau(&t);

    printf("===== TESTS PHASE 3 =====\n");
    test_cles(&t);
    test_chiffrement(&t);
    test_contacts(&t);
    test_sauvegarde(&t);
    test_divers(&t);

    // Bilan final d'exécution
    if (nb_ko == 0){
        printf("\n===== TOUT EST OK (%d tests) =====\n", nb_tests);
    } else {
        printf("\n===== ECHEC : %d test(s) sur %d en echec =====\n", nb_ko, nb_tests);
    }

    // Nettoyage des artefacts temporaires
    remove("t3_clair.txt");
    remove("t3_chiffre.bin");
    remove("t3_chiffre2.bin");
    remove("t3_chiffre.b64");
    remove("t3_dechiffre.txt");
    remove("t3_pub.txt");
    remove("t3_trousseau.diypg");
    remove("t3_faux.diypg");
    base64_cleanup();
    return nb_ko != 0;
}