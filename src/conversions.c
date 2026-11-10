/// \file conversions.c
/// \brief conversions base64 et echange des clefs publiques
/// \author Bousseksou Dorian, Boillat Clement, Napoletano Ethan, Mokhtari Tahar
///
/// Phase 2 : point 4.d (echange des clefs publiques), points 1 et 2 (chiffre <-> base64)
/// Phase 3 : points 5 et 6 (commandes bin-2b64 et b64-2bin de l'interprete)
/// Ne depend que du code deja dans le depot (phase1, other_base64, sha256) : pas besoin de GMP.
///
/// Par rapport aux fonctions de la phase 1.3, les fichiers base64 sont adaptes aux mails :
///   - le texte est coupe en lignes de 76 caracteres (comme la commande "base64" et les mails),
///   - a la lecture, les retours a la ligne et espaces sont ignores (les mails en ajoutent),
///   - un texte qui contient des caracteres hors de l'alphabet base64 est refuse.

#include "conversions.h"
#include "sha256.h"

//Outils :

/// lit tout un fichier dans un tableau alloue (a liberer avec free), termine par '\0'
/// \returns le tableau, NULL en cas d'erreur
static char *lire_fichier(const char *nom, size_t *taille){
    FILE *f = fopen(nom, "rb");
    if (f == NULL){
        perror(nom);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long lg = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *donnees = malloc(lg + 1);         // +1 pour le '\0' (et pour un fichier vide)
    if (donnees == NULL){
        fclose(f);
        return NULL;
    }
    *taille = fread(donnees, 1, lg, f);
    donnees[*taille] = '\0';
    fclose(f);
    return donnees;
}

/// ecrit n octets dans un fichier
/// \returns 1 si tout va bien, 0 sinon
static int ecrire_fichier(const char *nom, const void *donnees, size_t n, const char *mode){
    FILE *f = fopen(nom, mode);
    if (f == NULL){
        perror(nom);
        return 0;
    }
    size_t nbEcrits = fwrite(donnees, 1, n, f);
    if (fclose(f) != 0 || nbEcrits != n){
        perror(nom);
        return 0;
    }
    return 1;
}

/// 1 si c est un caractere de l'alphabet base64 (sans le '=')
static int caractere_base64(char c){
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= '0' && c <= '9') return 1;
    if (c == '+' || c == '/') return 1;
    return 0;
}

//Texte base64 :

/// enleve les espaces, tabulations et retours a la ligne d'un texte (sur place)
/// \returns la nouvelle longueur
size_t enlever_espaces(char *texte, size_t lg){
    size_t j = 0;
    for (size_t i = 0; i < lg; i++){
        char c = texte[i];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n'){
            texte[j] = c;
            j++;
        }
    }
    texte[j] = '\0';
    return j;
}

/// verifie qu'un texte (sans espaces) est du base64 correct :
///   - longueur multiple de 4,
///   - seulement A-Z a-z 0-9 + /,
///   - '=' seulement a la fin (0, 1 ou 2)
/// base64_decode (fourni) ne fait pas ces verifications et renvoie n'importe quoi sinon
/// \returns 1 si le texte est valide, 0 sinon
int base64_valide(const char *texte, size_t lg){
    if (lg % 4 != 0){
        return 0;
    }
    size_t nb_egal = 0;
    if (lg >= 1 && texte[lg - 1] == '='){
        nb_egal = 1;
        if (lg >= 2 && texte[lg - 2] == '='){
            nb_egal = 2;
        }
    }
    for (size_t i = 0; i < lg - nb_egal; i++){
        if (caractere_base64(texte[i]) == 0){
            return 0;
        }
    }
    return 1;
}

//Fichiers :

/// convertit un fichier binaire (par exemple un message chiffre) en fichier texte base64
/// le texte est coupe en lignes de LARGEUR_LIGNE_B64 caracteres
/// \returns 1 si tout va bien, 0 en cas d'erreur
int binaire_vers_base64(const char *src, const char *dst){
    // 1. lire le fichier binaire
    size_t lgBinaire;
    char *binaire = lire_fichier(src, &lgBinaire);
    if (binaire == NULL){
        return 0;
    }

    // 2. fichier vide : le base64 est vide aussi
    if (lgBinaire == 0){
        free(binaire);
        return ecrire_fichier(dst, "", 0, "w");
    }

    // 3. encoder (3 octets donnent 4 caracteres)
    size_t lgTexte;
    char *texte = base64_encode((unsigned char *)binaire, lgBinaire, &lgTexte);
    free(binaire);
    if (texte == NULL){
        return 0;
    }

    // 4. ecrire le texte par lignes de 76 caracteres
    FILE *fo = fopen(dst, "w");
    if (fo == NULL){
        perror(dst);
        free(texte);
        return 0;
    }
    size_t debut = 0;
    while (debut < lgTexte){
        size_t lgLigne = LARGEUR_LIGNE_B64;
        if (lgTexte - debut < lgLigne){
            lgLigne = lgTexte - debut;      // derniere ligne, plus courte
        }
        fwrite(texte + debut, 1, lgLigne, fo);
        fputc('\n', fo);
        debut = debut + lgLigne;
    }
    free(texte);

    if (fclose(fo) != 0){
        perror(dst);
        return 0;
    }
    return 1;
}

/// convertit un fichier texte base64 en fichier binaire
/// les espaces et retours a la ligne sont ignores (texte copie depuis un mail par exemple)
/// \returns 1 si tout va bien, 0 si le fichier est absent ou si ce n'est pas du base64 valide
int base64_vers_binaire(const char *src, const char *dst){
    // 1. lire le texte et enlever les espaces et retours a la ligne
    size_t lgTexte;
    char *texte = lire_fichier(src, &lgTexte);
    if (texte == NULL){
        return 0;
    }
    lgTexte = enlever_espaces(texte, lgTexte);

    // 2. texte vide : fichier binaire vide
    if (lgTexte == 0){
        free(texte);
        return ecrire_fichier(dst, "", 0, "wb");
    }

    // 3. verifier que c'est bien du base64
    if (base64_valide(texte, lgTexte) == 0){
        fprintf(stderr, "%s : ce n'est pas un texte base64 valide\n", src);
        free(texte);
        return 0;
    }

    // 4. decoder (4 caracteres redonnent 3 octets) et ecrire
    size_t lgBinaire;
    unsigned char *binaire = base64_decode(texte, lgTexte, &lgBinaire);
    free(texte);
    if (binaire == NULL){
        return 0;
    }
    int ok = ecrire_fichier(dst, binaire, lgBinaire, "wb");
    free(binaire);
    return ok;
}

//Echange des clefs publiques :
//
// Choix du format : base64.
//   - une clef publique (E, N) = 16 octets (2 x 8 octets, little endian),
//   - en base64 : 24 caracteres (en hexadecimal il en faudrait 32),
//   - les caracteres base64 passent sans probleme dans un mail,
//   - on a deja les fonctions base64 dans le projet.
// On ajoute une empreinte (debut du SHA-256 de la clef) : elle permet de verifier que la
// clef n'a pas ete abimee pendant l'envoi, et de la comparer de vive voix avec son proprietaire.
//
// Fichier de clef publique (a joindre au mail ou a copier dans le texte du mail) :
//   DIYPG CLE PUBLIQUE
//   cle : AQABAAAAAABBkb4qjh68Cg==
//   empreinte : 3f2a91c07b110d4e

/// convertit une clef en texte base64 de 24 caracteres (termine par '\0')
/// \param[out] texte : au moins TAILLE_CLE_B64 caracteres
/// \returns 1 si tout va bien, 0 sinon
int cle_vers_base64(rsaKey_t cle, char *texte, size_t taille_max){
    uint8_t octets[16];
    u64_to_bytes(cle.E, octets);
    u64_to_bytes(cle.N, octets + 8);

    size_t lg;
    char *b64 = base64_encode(octets, 16, &lg);
    if (b64 == NULL){
        return 0;
    }
    if (lg + 1 > taille_max){
        free(b64);
        return 0;
    }
    memcpy(texte, b64, lg);             // base64_encode ne met pas de '\0'
    texte[lg] = '\0';
    free(b64);
    return 1;
}

/// relit une clef ecrite par cle_vers_base64 (les espaces et retours a la ligne sont ignores)
/// \returns 1 si tout va bien, 0 si le texte n'est pas une clef valide
int base64_vers_cle(const char *texte, rsaKey_t *cle){
    char copie[64];
    if (strlen(texte) >= sizeof copie){
        return 0;
    }
    strcpy(copie, texte);
    size_t lg = enlever_espaces(copie, strlen(copie));

    if (base64_valide(copie, lg) == 0){
        return 0;
    }
    size_t nbOctets;
    unsigned char *octets = base64_decode(copie, lg, &nbOctets);
    if (octets == NULL){
        return 0;
    }
    if (nbOctets != 16){
        free(octets);
        return 0;
    }
    cle->E = bytes_to_u64(octets);
    cle->N = bytes_to_u64(octets + 8);
    free(octets);
    return 1;
}

/// calcule l'empreinte d'une clef : les 8 premiers octets du SHA-256 de ses 16 octets,
/// en hexadecimal (16 caracteres)
/// \param[out] empreinte : au moins TAILLE_EMPREINTE caracteres
void empreinte_cle(rsaKey_t cle, char *empreinte){
    uint8_t octets[16];
    u64_to_bytes(cle.E, octets);
    u64_to_bytes(cle.N, octets + 8);

    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, octets, 16);
    sha256_final(&ctx, hash);

    for (int i = 0; i < 8; i++){
        sprintf(empreinte + 2 * i, "%02x", hash[i]);
    }
    empreinte[16] = '\0';
}

/// ecrit une clef publique dans un fichier texte a envoyer par mail
/// \returns 1 si tout va bien, 0 sinon
int sauver_cle_publique(rsaKey_t cle, const char *fichier){
    char texte[TAILLE_CLE_B64];
    char empreinte[TAILLE_EMPREINTE];
    if (cle_vers_base64(cle, texte, sizeof texte) == 0){
        return 0;
    }
    empreinte_cle(cle, empreinte);

    FILE *f = fopen(fichier, "w");
    if (f == NULL){
        perror(fichier);
        return 0;
    }
    fprintf(f, "%s\ncle : %s\nempreinte : %s\n", ENTETE_CLE_PUBLIQUE, texte, empreinte);
    if (fclose(f) != 0){
        perror(fichier);
        return 0;
    }
    return 1;
}

/// recopie dans valeur le mot qui suit "etiquette" dans le texte (ex : "cle :")
/// \returns 1 si l'etiquette est trouvee, 0 sinon
static int lire_champ(const char *texte, const char *etiquette, char *valeur, size_t taille){
    const char *p = strstr(texte, etiquette);
    if (p == NULL){
        return 0;
    }
    p = p + strlen(etiquette);
    while (*p == ' ' || *p == '\t'){
        p++;                                    // sauter les espaces
    }
    size_t i = 0;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n' && i < taille - 1){
        valeur[i] = *p;
        i++;
        p++;
    }
    valeur[i] = '\0';
    return 1;
}

/// relit un fichier ecrit par sauver_cle_publique et verifie l'empreinte
/// (le fichier peut contenir d'autres lignes, par exemple s'il a ete copie depuis un mail)
/// \returns 1 si tout va bien, 0 si le fichier est absent, invalide ou si la clef a ete abimee
int charger_cle_publique(const char *fichier, rsaKey_t *cle){
    size_t taille;
    char *texte = lire_fichier(fichier, &taille);
    if (texte == NULL){
        return 0;
    }

    char b64[64];
    char empreinte_lue[64];
    int ok = 1;
    if (strstr(texte, ENTETE_CLE_PUBLIQUE) == NULL
        || lire_champ(texte, "cle :", b64, sizeof b64) == 0
        || lire_champ(texte, "empreinte :", empreinte_lue, sizeof empreinte_lue) == 0){
        fprintf(stderr, "%s : ce n'est pas un fichier de clef publique DIYPG\n", fichier);
        ok = 0;
    } else if (base64_vers_cle(b64, cle) == 0){
        fprintf(stderr, "%s : la clef n'est pas un texte base64 valide\n", fichier);
        ok = 0;
    } else {
        char empreinte[TAILLE_EMPREINTE];
        empreinte_cle(*cle, empreinte);
        if (strcmp(empreinte, empreinte_lue) != 0){
            fprintf(stderr, "%s : empreinte incorrecte, la clef a ete modifiee ou abimee\n", fichier);
            ok = 0;
        }
    }
    free(texte);
    return ok;
}

//Commandes de l'interprete :
//
// Pour les brancher dans l'interprete, une fois la ligne decoupee en mots :
//   if (strcmp(mots[0], "bin-2b64") == 0) ok = commande_bin_2b64(nb_mots, mots);
//   if (strcmp(mots[0], "b64-2bin") == 0) ok = commande_b64_2bin(nb_mots, mots);

/// commande "bin-2b64 <fileIn> <fileOut>" : fichier binaire (ex : message chiffre) -> fichier base64
/// \returns 1 si tout va bien, 0 en cas d'erreur
int commande_bin_2b64(int nb_mots, char **mots){
    if (nb_mots != 3){
        printf("Usage : bin-2b64 <fileIn> <fileOut>\n");
        return 0;
    }
    if (binaire_vers_base64(mots[1], mots[2]) == 0){
        return 0;
    }
    printf("%s converti en base64 dans %s\n", mots[1], mots[2]);
    return 1;
}

/// commande "b64-2bin <fileIn> <fileOut>" : fichier base64 -> fichier binaire
/// \returns 1 si tout va bien, 0 en cas d'erreur
int commande_b64_2bin(int nb_mots, char **mots){
    if (nb_mots != 3){
        printf("Usage : b64-2bin <fileIn> <fileOut>\n");
        return 0;
    }
    if (base64_vers_binaire(mots[1], mots[2]) == 0){
        return 0;
    }
    printf("%s converti en binaire dans %s\n", mots[1], mots[2]);
    return 1;
}
