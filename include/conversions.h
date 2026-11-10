/// \file conversions.h
/// \brief conversions base64 et echange des clefs publiques (phases 2 et 3)
/// ne depend que de phase1, other_base64 et sha256 : pas besoin de GMP
#ifndef CONVERSIONS_H
#define CONVERSIONS_H

#include "phase1.h"

// longueur des lignes base64 dans les fichiers (norme des mails, comme la commande "base64")
#define LARGEUR_LIGNE_B64 76

// une clef publique en base64 : 16 octets (E et N) -> 24 caracteres
#define TAILLE_CLE_B64 25           // 24 caracteres + '\0'
// empreinte d'une clef : 8 premiers octets du SHA-256, en hexadecimal
#define TAILLE_EMPREINTE 17         // 16 caracteres + '\0'

#define ENTETE_CLE_PUBLIQUE "DIYPG CLE PUBLIQUE"

/* ---------- texte base64 ---------- */
size_t enlever_espaces(char *texte, size_t lg);
int    base64_valide(const char *texte, size_t lg);

/* ---------- fichiers (points 1 et 2 de la phase 2, points 5 et 6 de la phase 3) ---------- */
int binaire_vers_base64(const char *src, const char *dst);
int base64_vers_binaire(const char *src, const char *dst);

// Alias pour compatibilite avec tests_phase2.c et interprete.c
#define fichier_vers_base64 binaire_vers_base64
#define base64_vers_fichier base64_vers_binaire

/* ---------- echange des clefs publiques (point 4.d de la phase 2) ---------- */
int  cle_vers_base64(rsaKey_t cle, char *texte, size_t taille_max);
int  base64_vers_cle(const char *texte, rsaKey_t *cle);
void empreinte_cle(rsaKey_t cle, char *empreinte);
int  sauver_cle_publique(rsaKey_t cle, const char *fichier);
int  charger_cle_publique(const char *fichier, rsaKey_t *cle);

/* ---------- commandes de l'interprete (points 5 et 6 de la phase 3) ---------- */
// mots : la commande decoupee en mots, mots[0] est le nom de la commande
// renvoient 1 si tout va bien, 0 en cas d'erreur (message deja affiche)
int commande_bin_2b64(int nb_mots, char **mots);
int commande_b64_2bin(int nb_mots, char **mots);

#endif