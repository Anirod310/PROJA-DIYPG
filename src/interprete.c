/// \file interprete.c
/// \brief phase 3 : interprete de commandes et annuaire de clefs
/// \author Bousseksou Dorian, Boillat Clement, Napoletano Ethan, Mokhtari Tahar
///
/// V1.1 : gestion des clefs de l'utilisateur
///   quit, help, listkeys, newkeys, rmkeys, crypt, uncrypt, bin-2b64, b64-2bin,
///   save, load, savepub, show
/// V2 : gestion des contacts (clefs publiques des correspondants)
///   listcontacts, addcontact, modifycontact, addkeys, rmcontact
///   + crypt, rmkeys, show acceptent "contact/clef"

#include <sys/stat.h>   // chmod
#include "interprete.h"
#include "sha256.h"

#define MAX_MOTS 8                 // nombre maximum de mots dans une commande
#define MAGIQUE "DIYPG3"           // debut d'un fichier de sauvegarde (en clair)
#define TAILLE_MAGIQUE 6
#define VERIF "TROUSSOK"           // debut du contenu dechiffre : sert a verifier le mot de passe
#define TAILLE_VERIF 8
#define TAILLE_SEL 16

//Outils :

// copie une chaine en s'assurant qu'elle se termine par '\0'
static void copier(char *dst, const char *src, size_t taille){
    strncpy(dst, src, taille - 1);
    dst[taille - 1] = '\0';
}

/// affiche invite puis lit une ligne dans entree (sans le retour a la ligne)
// 1 si une ligne a ete lue, 0 en fin de fichier
static int lire_ligne(FILE *entree, const char *invite, char *buf, size_t taille){
    printf("%s", invite);
    fflush(stdout);
    if (fgets(buf, (int)taille, entree) == NULL){
        return 0;
    }
    buf[strcspn(buf, "\r\n")] = '\0';   // enlever le retour a la ligne
    if (entree != stdin){
        printf("%s\n", buf);              // en lecture depuis un fichier, on affiche ce qui est lu
    }
    return 1;
}

// un identificateur ne doit pas etre vide, ni trop long, ni contenir '/'
static int id_valide(const char *id){
    if (strlen(id) == 0 || strlen(id) >= TAILLE_ID || strchr(id, '/') != NULL){
        printf("Identificateur invalide : 1 a %d caracteres, sans '/'\n", TAILLE_ID - 1);
        return 0;
    }
    return 1;
}

static int type_valide(const char *type){
    if (strcmp(type, "crypt") == 0 || strcmp(type, "sign") == 0){
        return 1;
    }
    printf("Type invalide : \"crypt\" ou \"sign\"\n");
    return 0;
}

static void afficher_cle(const char *nom, rsaKey_t k){
    printf("  %s : E = 0x%016" PRIx64 "  N = 0x%016" PRIx64 "\n", nom, k.E, k.N);
}

//Recherche :

// l'indice de la clef id de l'utilisateur, -1 si elle n'existe pas
static int chercher_cle(const trousseau_t *t, const char *id){
    for (int i = 0; i < t->nb_cles; i++){
        if (strcmp(t->cles[i].id, id) == 0){
            return i;
        }
    }
    return -1;
}

// l'indice du contact id, -1 s'il n'existe pas
static int chercher_contact(const trousseau_t *t, const char *id){
    for (int i = 0; i < t->nb_contacts; i++){
        if (strcmp(t->contacts[i].id, id) == 0){
            return i;
        }
    }
    return -1;
}

// cherche un contact par son identificateur, puis par son nom
static int chercher_contact_id_ou_nom(const trousseau_t *t, const char *texte){
    int i = chercher_contact(t, texte);
    if (i >= 0){
        return i;
    }
    for (i = 0; i < t->nb_contacts; i++){
        if (strcmp(t->contacts[i].nom, texte) == 0){
            return i;
        }
    }
    return -1;
}

//  l'indice de la clef id du contact c, -1 si elle n'existe pas
static int chercher_cle_contact(const contact_t *c, const char *id){
    for (int i = 0; i < c->nb_cles; i++){
        if (strcmp(c->cles[i].id, id) == 0){
            return i;
        }
    }
    return -1;
}

/// trouve une clef publique de type "type" 
static int trouver_cle_publique(const trousseau_t *t, const char *ref, const char *type, rsaKey_t *pub){
    char copie[2 * TAILLE_ID];
    copier(copie, ref, sizeof copie);
    char *barre = strchr(copie, '/');

    // cas "contact/clef"
    if (barre != NULL){
        *barre = '\0';                       // copie = contact, barre + 1 = clef
        int ic = chercher_contact(t, copie);
        if (ic < 0){
            printf("Contact inconnu : %s\n", copie);
            return 0;
        }
        int ik = chercher_cle_contact(&t->contacts[ic], barre + 1);
        if (ik < 0){
            printf("Le contact %s n'a pas de clef %s\n", copie, barre + 1);
            return 0;
        }
        if (strcmp(t->contacts[ic].cles[ik].type, type) != 0){
            printf("La clef %s doit etre de type %s\n", ref, type);
            return 0;
        }
        *pub = t->contacts[ic].cles[ik].pub;
        return 1;
    }

    // cas "clef" de l'utilisateur
    int i = chercher_cle(t, ref);
    if (i >= 0){
        if (strcmp(t->cles[i].type, type) != 0){
            printf("La clef %s doit etre de type %s\n", ref, type);
            return 0;
        }
        *pub = t->cles[i].cles.pubKey;
        return 1;
    }

    // cas "contact" : il doit avoir exactement une clef du bon type
    int ic = chercher_contact(t, ref);
    if (ic < 0){
        printf("Clef ou contact inconnu : %s\n", ref);
        return 0;
    }
    int trouve = -1;
    int nb = 0;
    for (int k = 0; k < t->contacts[ic].nb_cles; k++){
        if (strcmp(t->contacts[ic].cles[k].type, type) == 0){
            trouve = k;
            nb++;
        }
    }
    if (nb == 0){
        printf("Le contact %s n'a pas de clef de type %s\n", ref, type);
        return 0;
    }
    if (nb > 1){
        printf("Le contact %s a plusieurs clefs %s : precisez %s/<clef>\n", ref, type, ref);
        return 0;
    }
    *pub = t->contacts[ic].cles[trouve].pub;
    return 1;
}

//Sauvegarde chiffree :


/// chiffre (ou dechiffre, c'est la meme operation) les donnees avec le mot de passe
static void xor_mot_de_passe(uint8_t *donnees, size_t taille, const uint8_t *sel, const char *mdp){
    BYTE flux[SHA256_BLOCK_SIZE];
    for (size_t i = 0; i < taille; i++){
        if (i % SHA256_BLOCK_SIZE == 0){
            // nouveau bloc de 32 octets de flux
            uint8_t numero[8];
            u64_to_bytes(i / SHA256_BLOCK_SIZE, numero);
            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, sel, TAILLE_SEL);
            sha256_update(&ctx, (const BYTE *)mdp, strlen(mdp));
            sha256_update(&ctx, numero, 8);
            sha256_final(&ctx, flux);
        }
        donnees[i] = donnees[i] ^ flux[i % SHA256_BLOCK_SIZE];
    }
}

// sauvegarde le trousseau dans un fichier chiffre avec le mot de passe
// 1 si tout va bien, 0 sinon
int sauver_trousseau(const trousseau_t *t, const char *fichier, const char *mot_de_passe){
    size_t taille = TAILLE_VERIF + sizeof(trousseau_t);
    uint8_t * contenu = malloc(taille);
    if (contenu == NULL){
        return 0;
    }
    memcpy(contenu, VERIF, TAILLE_VERIF);
    memcpy(contenu + TAILLE_VERIF, t, sizeof(trousseau_t));

    // sel au hasard : deux sauvegardes avec le meme mot de passe donnent des fichiers differents
    uint8_t sel[TAILLE_SEL];
    for (int i = 0; i < TAILLE_SEL; i++){
        sel[i] = (uint8_t)(rand() % 256);
    }
    xor_mot_de_passe(contenu, taille, sel, mot_de_passe);

    FILE *f = fopen(fichier, "wb");
    if (f == NULL){
        perror(fichier);
        free(contenu);
        return 0;
    }
    fwrite(MAGIQUE, 1, TAILLE_MAGIQUE, f);
    fwrite(sel, 1, TAILLE_SEL, f);
    size_t nbEcrits = fwrite(contenu, 1, taille, f);
    free(contenu);
    if (fclose(f) != 0 || nbEcrits != taille){
        perror(fichier);
        return 0;
    }

    // droits systeme : lecture et ecriture pour le proprietaire seulement (rw-------)
    chmod(fichier, S_IRUSR | S_IWUSR);
    return 1;
}

// recharge un trousseau sauvegarde par sauver_trousseau
//1 si tout va bien, 0 si le fichier est absent, abime ou le mot de passe faux
int charger_trousseau(trousseau_t *t, const char *fichier, const char *mot_de_passe){
    FILE *f = fopen(fichier, "rb");
    if (f == NULL){
        perror(fichier);
        return 0;
    }

    char magique[TAILLE_MAGIQUE];
    uint8_t sel[TAILLE_SEL];
    size_t taille = TAILLE_VERIF + sizeof(trousseau_t);
    uint8_t *contenu = malloc(taille);
    if (contenu == NULL){
        fclose(f);
        return 0;
    }

    int ok = 1;
    if (fread(magique, 1, TAILLE_MAGIQUE, f) != TAILLE_MAGIQUE
        || memcmp(magique, MAGIQUE, TAILLE_MAGIQUE) != 0){
        printf("%s : ce n'est pas un fichier de sauvegarde DIYPG\n", fichier);
        ok = 0;
    } else if (fread(sel, 1, TAILLE_SEL, f) != TAILLE_SEL || fread(contenu, 1, taille, f) != taille){
        printf("%s : fichier de sauvegarde tronque\n", fichier);
        ok = 0;
    } else {
        xor_mot_de_passe(contenu, taille, sel, mot_de_passe);
        if (memcmp(contenu, VERIF, TAILLE_VERIF) != 0){
            printf("Mot de passe incorrect\n");
            ok = 0;
        }
    }
    fclose(f);

    if (ok == 1){
        trousseau_t lu;
        memcpy(&lu, contenu + TAILLE_VERIF, sizeof lu);
        // verifier que les compteurs sont coherents avant de remplacer le trousseau
        if (lu.nb_cles < 0 || lu.nb_cles > MAX_CLES || lu.nb_contacts < 0 || lu.nb_contacts > MAX_CONTACTS){
            printf("%s : fichier de sauvegarde abime\n", fichier);
            ok = 0;
        } else {
            *t = lu;
        }
    }
    free(contenu);
    return ok;
}

//Commandes V1.1 :

static int cmd_help(void){
    printf("Clefs de l'utilisateur :\n"
           "  newkeys <keyid> <crypt|sign>        cree une paire de clefs\n"
           "  listkeys [<keyid>]                  liste les clefs (identificateur et type)\n"
           "  show <keyid> [pub] [priv]           affiche les clefs en hexadecimal\n"
           "  rmkeys <keyid>                      supprime une paire de clefs\n"
           "  savepub <keyid> <fichier>           exporte la clef publique (base64)\n"
           "Chiffrement :\n"
           "  crypt <fileIn> <fileOut> <keyid>    chiffre (keyid, contact ou contact/clef)\n"
           "  uncrypt <fileIn> <fileOut> <keyid>  dechiffre avec une de mes clefs\n"
           "  bin-2b64 <fileIn> <fileOut>         binaire -> base64\n"
           "  b64-2bin <fileIn> <fileOut>         base64 -> binaire\n"
           "Contacts :\n"
           "  addcontact <id>                     ajoute un contact\n"
           "  modifycontact <id>                  modifie un contact\n"
           "  listcontacts [<id>|<nom>]           liste les contacts et leurs clefs\n"
           "  addkeys <id>|<nom>                  ajoute une clef publique a un contact\n"
           "  rmkeys <contact>/<clef>             supprime une clef d'un contact\n"
           "  rmcontact <id>                      supprime un contact et ses clefs\n"
           "Sauvegarde :\n"
           "  save [<fichier>]                    sauvegarde chiffree (mot de passe)\n"
           "  load [<fichier>]                    recharge une sauvegarde\n"
           "  help, quit\n");
    return COMMANDE_OK;
}

// newkeys <keyid> <type>
static int cmd_newkeys(trousseau_t *t, char *id, char *type){
    if (id_valide(id) == 0 || type_valide(type) == 0){
        return COMMANDE_ERREUR;
    }
    if (chercher_cle(t, id) >= 0){
        printf("La clef %s existe deja\n", id);
        return COMMANDE_ERREUR;
    }
    if (t->nb_cles >= MAX_CLES){
        printf("Trop de clefs (%d au maximum)\n", MAX_CLES);
        return COMMANDE_ERREUR;
    }
    cle_t *c = &t->cles[t->nb_cles];
    if (genKeysGMP(&c->cles.pubKey, &c->cles.privKey, MAX_PRIME_GMP) == 0){
        return COMMANDE_ERREUR;
    }
    copier(c->id, id, TAILLE_ID);
    copier(c->type, type, TAILLE_TYPE);
    t->nb_cles++;
    printf("Paire de clefs %s (%s) creee\n", id, type);
    return COMMANDE_OK;
}

// listkeys [<keyid>]
static int cmd_listkeys(const trousseau_t *t, char *id){
    if (id != NULL){
        int i = chercher_cle(t, id);
        if (i < 0){
            printf("Clef inconnue : %s\n", id);
            return COMMANDE_ERREUR;
        }
        printf("  %-20s %s\n", t->cles[i].id, t->cles[i].type);
        return COMMANDE_OK;
    }
    printf("%d clef(s) :\n", t->nb_cles);
    for (int i = 0; i < t->nb_cles; i++){
        printf("  %-20s %s\n", t->cles[i].id, t->cles[i].type);
    }
    return COMMANDE_OK;
}

// rmkeys <keyid>  ou  rmkeys <contact>/<clef>
static int cmd_rmkeys(trousseau_t *t, char *ref){
    char copie[2 * TAILLE_ID];
    copier(copie, ref, sizeof copie);
    char *barre = strchr(copie, '/');

    // clef d'un contact (V2) : on ne supprime que celle-la
    if (barre != NULL){
        *barre = '\0';
        int ic = chercher_contact(t, copie);
        if (ic < 0){
            printf("Contact inconnu : %s\n", copie);
            return COMMANDE_ERREUR;
        }
        contact_t *c = &t->contacts[ic];
        int ik = chercher_cle_contact(c, barre + 1);
        if (ik < 0){
            printf("Le contact %s n'a pas de clef %s\n", copie, barre + 1);
            return COMMANDE_ERREUR;
        }
        // decaler les clefs suivantes d'une case vers la gauche
        for (int k = ik; k < c->nb_cles - 1; k++){
            c->cles[k] = c->cles[k + 1];
        }
        c->nb_cles--;
        printf("Clef %s supprimee\n", ref);
        return COMMANDE_OK;
    }

    // clef de l'utilisateur
    int i = chercher_cle(t, ref);
    if (i < 0){
        printf("Clef inconnue : %s\n", ref);
        return COMMANDE_ERREUR;
    }
    for (int k = i; k < t->nb_cles - 1; k++){
        t->cles[k] = t->cles[k + 1];
    }
    t->nb_cles--;
    printf("Clef %s supprimee\n", ref);
    return COMMANDE_OK;
}

// crypt <fileIn> <fileOut> <keyid | contact | contact/clef>
static int cmd_crypt(const trousseau_t *t, char *in, char *out, char *ref){
    rsaKey_t pub;
    if (trouver_cle_publique(t, ref, "crypt", &pub) == 0){
        return COMMANDE_ERREUR;
    }
    if (chiffrer_fichier_blocs(in, out, pub) == 0){
        return COMMANDE_ERREUR;
    }
    printf("%s chiffre dans %s\n", in, out);
    return COMMANDE_OK;
}

// uncrypt <fileIn> <fileOut> <keyid> : seulement avec une clef de l'utilisateur (clef privee)
static int cmd_uncrypt(const trousseau_t *t, char *in, char *out, char *id){
    int i = chercher_cle(t, id);
    if (i < 0){
        printf("Clef inconnue : %s (il faut une de vos clefs, pas celle d'un contact)\n", id);
        return COMMANDE_ERREUR;
    }
    if (strcmp(t->cles[i].type, "crypt") != 0){
        printf("La clef %s doit etre de type crypt\n", id);
        return COMMANDE_ERREUR;
    }
    if (dechiffrer_fichier_blocs(in, out, t->cles[i].cles.privKey) == 0){
        return COMMANDE_ERREUR;
    }
    printf("%s dechiffre dans %s\n", in, out);
    return COMMANDE_OK;
}

// savepub <keyid> <fichier>
static int cmd_savepub(const trousseau_t *t, char *id, char *fichier){
    int i = chercher_cle(t, id);
    if (i < 0){
        printf("Clef inconnue : %s\n", id);
        return COMMANDE_ERREUR;
    }
    if (sauver_cle_publique(t->cles[i].cles.pubKey, fichier) == 0){
        return COMMANDE_ERREUR;
    }
    printf("Clef publique %s ecrite dans %s\n", id, fichier);
    return COMMANDE_OK;
}

// show <keyid | contact/clef> [pub] [priv]
static int cmd_show(const trousseau_t *t, int nb_mots, char **mots){
    char *ref = mots[1];
    int pub = 0;
    int priv = 0;
    for (int k = 2; k < nb_mots; k++){
        if (strcmp(mots[k], "pub") == 0){
            pub = 1;
        } else if (strcmp(mots[k], "priv") == 0){
            priv = 1;
        } else {
            printf("Option inconnue : %s (pub ou priv)\n", mots[k]);
            return COMMANDE_ERREUR;
        }
    }
    if (pub == 0 && priv == 0){    // sans option : les deux
        pub = 1;
        priv = 1;
    }

    // clef d'un contact : seulement la clef publique
    if (strchr(ref, '/') != NULL){
        char copie[2 * TAILLE_ID];
        copier(copie, ref, sizeof copie);
        char *barre = strchr(copie, '/');
        *barre = '\0';
        int ic = chercher_contact(t, copie);
        int ik = -1;
        if (ic >= 0){
            ik = chercher_cle_contact(&t->contacts[ic], barre + 1);
        }
        if (ik < 0){
            printf("Clef inconnue : %s\n", ref);
            return COMMANDE_ERREUR;
        }
        printf("%s (%s) :\n", ref, t->contacts[ic].cles[ik].type);
        afficher_cle("publique", t->contacts[ic].cles[ik].pub);
        if (priv == 1){
            printf("  (pas de clef privee pour un contact)\n");
        }
        return COMMANDE_OK;
    }

    int i = chercher_cle(t, ref);
    if (i < 0){
        printf("Clef inconnue : %s\n", ref);
        return COMMANDE_ERREUR;
    }
    printf("%s (%s) :\n", ref, t->cles[i].type);
    if (pub == 1){
        afficher_cle("publique", t->cles[i].cles.pubKey);
    }
    if (priv == 1){
        afficher_cle("privee  ", t->cles[i].cles.privKey);
    }
    return COMMANDE_OK;
}

// save [<fichier>] et load [<fichier>] : demandent un mot de passe
static int cmd_save_load(trousseau_t *t, int sauver, char *fichier, FILE *entree){
    if (fichier == NULL){
        fichier = FICHIER_DEFAUT;
    }
    char mdp[128];
    if (lire_ligne(entree, "Mot de passe : ", mdp, sizeof mdp) == 0 || strlen(mdp) == 0){
        printf("Mot de passe vide : abandon\n");
        return COMMANDE_ERREUR;
    }
    if (sauver == 1){
        if (sauver_trousseau(t, fichier, mdp) == 0){
            return COMMANDE_ERREUR;
        }
        printf("Trousseau sauvegarde dans %s\n", fichier);
    } else {
        if (charger_trousseau(t, fichier, mdp) == 0){
            return COMMANDE_ERREUR;
        }
        printf("Trousseau charge depuis %s (%d clef(s), %d contact(s))\n", fichier, t->nb_cles, t->nb_contacts);
    }
    return COMMANDE_OK;
}

//Commandes V2 (contacts) :

static void afficher_contact(const contact_t *c){
    printf("  %s : %s %s", c->id, c->prenom, c->nom);
    if (strlen(c->commentaire) > 0){
        printf(" (%s)", c->commentaire);
    }
    printf("\n");
    for (int k = 0; k < c->nb_cles; k++){
        printf("      - %-16s %s\n", c->cles[k].id, c->cles[k].type);
    }
}

// listcontacts [<id> | <nom>]
static int cmd_listcontacts(const trousseau_t *t, char *filtre){
    if (filtre != NULL){
        int nb = 0;
        for (int i = 0; i < t->nb_contacts; i++){
            if (strcmp(t->contacts[i].id, filtre) == 0 || strcmp(t->contacts[i].nom, filtre) == 0){
                afficher_contact(&t->contacts[i]);
                nb++;
            }
        }
        if (nb == 0){
            printf("Aucun contact %s\n", filtre);
            return COMMANDE_ERREUR;
        }
        return COMMANDE_OK;
    }
    printf("%d contact(s) :\n", t->nb_contacts);
    for (int i = 0; i < t->nb_contacts; i++){
        afficher_contact(&t->contacts[i]);
    }
    return COMMANDE_OK;
}

// addcontact <id> : cree le contact puis demande nom, prenom et commentaire
static int cmd_addcontact(trousseau_t *t, char *id, FILE *entree){
    if (id_valide(id) == 0){
        return COMMANDE_ERREUR;
    }
    if (chercher_contact(t, id) >= 0){
        printf("Le contact %s existe deja\n", id);
        return COMMANDE_ERREUR;
    }
    if (t->nb_contacts >= MAX_CONTACTS){
        printf("Trop de contacts (%d au maximum)\n", MAX_CONTACTS);
        return COMMANDE_ERREUR;
    }
    contact_t *c = &t->contacts[t->nb_contacts];
    memset(c, 0, sizeof *c);
    copier(c->id, id, TAILLE_ID);

    // menu de saisie
    char ligne[TAILLE_COMMENTAIRE];
    if (lire_ligne(entree, "Nom : ", ligne, sizeof ligne) == 1){
        copier(c->nom, ligne, TAILLE_NOM);
    }
    if (lire_ligne(entree, "Prenom : ", ligne, sizeof ligne) == 1){
        copier(c->prenom, ligne, TAILLE_NOM);
    }
    if (lire_ligne(entree, "Commentaire : ", ligne, sizeof ligne) == 1){
        copier(c->commentaire, ligne, TAILLE_COMMENTAIRE);
    }
    t->nb_contacts++;
    printf("Contact %s ajoute\n", id);
    return COMMANDE_OK;
}

// modifycontact <id> : affiche le contact et un menu de modification
static int cmd_modifycontact(trousseau_t *t, char *id, FILE *entree){
    int i = chercher_contact(t, id);
    if (i < 0){
        printf("Contact inconnu : %s\n", id);
        return COMMANDE_ERREUR;
    }
    contact_t *c = &t->contacts[i];
    char choix[16];
    char ligne[TAILLE_COMMENTAIRE];

    while (1){
        afficher_contact(c);
        printf("1. nom  2. prenom  3. commentaire  0. terminer\n");
        if (lire_ligne(entree, "Choix : ", choix, sizeof choix) == 0 || strcmp(choix, "0") == 0){
            return COMMANDE_OK;
        }
        if (strcmp(choix, "1") == 0 || strcmp(choix, "2") == 0 || strcmp(choix, "3") == 0){
            if (lire_ligne(entree, "Nouvelle valeur : ", ligne, sizeof ligne) == 0){
                return COMMANDE_OK;
            }
            if (strcmp(choix, "1") == 0){
                copier(c->nom, ligne, TAILLE_NOM);
            } else if (strcmp(choix, "2") == 0){
                copier(c->prenom, ligne, TAILLE_NOM);
            } else {
                copier(c->commentaire, ligne, TAILLE_COMMENTAIRE);
            }
        } else {
            printf("Choix inconnu\n");
        }
    }
}

// addkeys <id> | <nom> : ajoute une clef publique (fichier ecrit par savepub) a un contact
static int cmd_addkeys(trousseau_t *t, char *texte, FILE *entree){
    int i = chercher_contact_id_ou_nom(t, texte);
    if (i < 0){
        printf("Contact inconnu : %s\n", texte);
        return COMMANDE_ERREUR;
    }
    contact_t *c = &t->contacts[i];
    if (c->nb_cles >= MAX_CLES_CONTACT){
        printf("Trop de clefs pour ce contact (%d au maximum)\n", MAX_CLES_CONTACT);
        return COMMANDE_ERREUR;
    }

    char id[TAILLE_ID + 16];
    char type[TAILLE_TYPE + 16];
    char fichier[256];
    if (lire_ligne(entree, "Identificateur de la clef : ", id, sizeof id) == 0 || id_valide(id) == 0){
        return COMMANDE_ERREUR;
    }
    if (chercher_cle_contact(c, id) >= 0){
        printf("Le contact %s a deja une clef %s\n", c->id, id);
        return COMMANDE_ERREUR;
    }
    if (lire_ligne(entree, "Type (crypt/sign) : ", type, sizeof type) == 0 || type_valide(type) == 0){
        return COMMANDE_ERREUR;
    }
    if (lire_ligne(entree, "Fichier de la clef publique : ", fichier, sizeof fichier) == 0){
        return COMMANDE_ERREUR;
    }

    cle_contact_t *k = &c->cles[c->nb_cles];
    if (charger_cle_publique(fichier, &k->pub) == 0){
        return COMMANDE_ERREUR;
    }
    copier(k->id, id, TAILLE_ID);
    copier(k->type, type, TAILLE_TYPE);
    c->nb_cles++;
    printf("Clef %s/%s ajoutee\n", c->id, id);
    return COMMANDE_OK;
}

// rmcontact <id>
static int cmd_rmcontact(trousseau_t *t, char *id){
    int i = chercher_contact(t, id);
    if (i < 0){
        printf("Contact inconnu : %s\n", id);
        return COMMANDE_ERREUR;
    }
    for (int k = i; k < t->nb_contacts - 1; k++){
        t->contacts[k] = t->contacts[k + 1];
    }
    t->nb_contacts--;
    printf("Contact %s supprime\n", id);
    return COMMANDE_OK;
}

//Interprete :

void init_trousseau(trousseau_t *t){
    memset(t, 0, sizeof *t);
}

// verifie le nombre de mots d'une commande
static int verifier_nb(int nb_mots, int min, int max, const char *usage){
    if (nb_mots < min || nb_mots > max){
        printf("Usage : %s\n", usage);
        return 0;
    }
    return 1;
}

// execute une ligne de commande
//COMMANDE_OK, COMMANDE_ERREUR ou COMMANDE_QUITTER
int executer_commande(trousseau_t *t, char *ligne, FILE *entree){
    // 1. decouper la ligne en mots
    char *mots[MAX_MOTS];
    int nb = 0;
    char *mot = strtok(ligne, " \t\r\n");
    while (mot != NULL && nb < MAX_MOTS){
        mots[nb] = mot;
        nb++;
        mot = strtok(NULL, " \t\r\n");
    }
    if (nb == 0){
        return COMMANDE_OK;               // ligne vide
    }
    char *cmd = mots[0];

    // 2. executer la commande
    if (strcmp(cmd, "quit") == 0){
        return COMMANDE_QUITTER;
    }
    if (strcmp(cmd, "help") == 0){
        return cmd_help();
    }
    if (strcmp(cmd, "listkeys") == 0){
        if (verifier_nb(nb, 1, 2, "listkeys [<keyid>]") == 0) return COMMANDE_ERREUR;
        if (nb == 2){
            return cmd_listkeys(t, mots[1]);
        }
        return cmd_listkeys(t, NULL);
    }
    if (strcmp(cmd, "newkeys") == 0){
        if (verifier_nb(nb, 3, 3, "newkeys <keyid> <crypt|sign>") == 0) return COMMANDE_ERREUR;
        return cmd_newkeys(t, mots[1], mots[2]);
    }
    if (strcmp(cmd, "rmkeys") == 0){
        if (verifier_nb(nb, 2, 2, "rmkeys <keyid> | rmkeys <contact>/<clef>") == 0) return COMMANDE_ERREUR;
        return cmd_rmkeys(t, mots[1]);
    }
    if (strcmp(cmd, "crypt") == 0){
        if (verifier_nb(nb, 4, 4, "crypt <fileIn> <fileOut> <keyid>") == 0) return COMMANDE_ERREUR;
        return cmd_crypt(t, mots[1], mots[2], mots[3]);
    }
    if (strcmp(cmd, "uncrypt") == 0){
        if (verifier_nb(nb, 4, 4, "uncrypt <fileIn> <fileOut> <keyid>") == 0) return COMMANDE_ERREUR;
        return cmd_uncrypt(t, mots[1], mots[2], mots[3]);
    }
    if (strcmp(cmd, "bin-2b64") == 0){
        if (verifier_nb(nb, 3, 3, "bin-2b64 <fileIn> <fileOut>") == 0) return COMMANDE_ERREUR;
        if (binaire_vers_base64(mots[1], mots[2]) == 0) return COMMANDE_ERREUR;
        printf("%s converti en base64 dans %s\n", mots[1], mots[2]);
        return COMMANDE_OK;
    }
    if (strcmp(cmd, "b64-2bin") == 0){
        if (verifier_nb(nb, 3, 3, "b64-2bin <fileIn> <fileOut>") == 0) return COMMANDE_ERREUR;
        if (base64_vers_binaire(mots[1], mots[2]) == 0) return COMMANDE_ERREUR;
        printf("%s converti en binaire dans %s\n", mots[1], mots[2]);
        return COMMANDE_OK;
    }
    if (strcmp(cmd, "save") == 0 || strcmp(cmd, "load") == 0){
        if (verifier_nb(nb, 1, 2, "save|load [<fichier>]") == 0) return COMMANDE_ERREUR;
        int sauver = 0;
        if (strcmp(cmd, "save") == 0){
            sauver = 1;
        }
        if (nb == 2){
            return cmd_save_load(t, sauver, mots[1], entree);
        }
        return cmd_save_load(t, sauver, NULL, entree);
    }
    if (strcmp(cmd, "savepub") == 0){
        if (verifier_nb(nb, 3, 3, "savepub <keyid> <fichier>") == 0) return COMMANDE_ERREUR;
        return cmd_savepub(t, mots[1], mots[2]);
    }
    if (strcmp(cmd, "show") == 0){
        if (verifier_nb(nb, 2, 4, "show <keyid> [pub] [priv]") == 0) return COMMANDE_ERREUR;
        return cmd_show(t, nb, mots);
    }
    if (strcmp(cmd, "listcontacts") == 0){
        if (verifier_nb(nb, 1, 2, "listcontacts [<id>|<nom>]") == 0) return COMMANDE_ERREUR;
        if (nb == 2){
            return cmd_listcontacts(t, mots[1]);
        }
        return cmd_listcontacts(t, NULL);
    }
    if (strcmp(cmd, "addcontact") == 0){
        if (verifier_nb(nb, 2, 2, "addcontact <id>") == 0) return COMMANDE_ERREUR;
        return cmd_addcontact(t, mots[1], entree);
    }
    if (strcmp(cmd, "modifycontact") == 0){
        if (verifier_nb(nb, 2, 2, "modifycontact <id>") == 0) return COMMANDE_ERREUR;
        return cmd_modifycontact(t, mots[1], entree);
    }
    if (strcmp(cmd, "addkeys") == 0){
        if (verifier_nb(nb, 2, 2, "addkeys <id>|<nom>") == 0) return COMMANDE_ERREUR;
        return cmd_addkeys(t, mots[1], entree);
    }
    if (strcmp(cmd, "rmcontact") == 0){
        if (verifier_nb(nb, 2, 2, "rmcontact <id>") == 0) return COMMANDE_ERREUR;
        return cmd_rmcontact(t, mots[1]);
    }

    printf("Commande inconnue : %s (tapez help)\n", cmd);
    return COMMANDE_ERREUR;
}

// boucle principale : lit et execute les commandes jusqu'a "quit" ou la fin de l'entree
void lancer_interprete(trousseau_t *t, FILE *entree){
    char ligne[512];
    printf("DIYPG - tapez help pour la liste des commandes\n");
    while (lire_ligne(entree, "diypg> ", ligne, sizeof ligne) == 1){
        if (executer_commande(t, ligne, entree) == COMMANDE_QUITTER){
            return;
        }
    }
    printf("\n");
}
