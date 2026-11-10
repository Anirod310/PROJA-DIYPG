/// \file interprete.h
/// \brief Phase 3 : interprete de commandes et annuaire de clefs (V1.1 et V2)
#ifndef INTERPRETE_H
#define INTERPRETE_H

#include <inttypes.h>
#include "phase2.h"

#define TAILLE_ID          32
#define TAILLE_TYPE        8
#define TAILLE_NOM         64
#define TAILLE_COMMENTAIRE 128

#define MAX_CLES           32
#define MAX_CONTACTS       32
#define MAX_CLES_CONTACT   8

#define FICHIER_DEFAUT     "trousseau.diypg"

#define COMMANDE_OK        1
#define COMMANDE_ERREUR    0
#define COMMANDE_QUITTER   2

// Paire de clefs de l'utilisateur
typedef struct {
    char id[TAILLE_ID];
    char type[TAILLE_TYPE];   // "crypt" ou "sign"
    keyPair_t cles;
} cle_t;

// Clef publique associee a un contact
typedef struct {
    char id[TAILLE_ID];
    char type[TAILLE_TYPE];   // "crypt" ou "sign"
    rsaKey_t pub;
} cle_contact_t;

// Contact de l'annuaire (V2)
typedef struct {
    char id[TAILLE_ID];
    char nom[TAILLE_NOM];
    char prenom[TAILLE_NOM];
    char commentaire[TAILLE_COMMENTAIRE];
    cle_contact_t cles[MAX_CLES_CONTACT];
    int nb_cles;
} contact_t;

// Trousseau complet (clefs personnelles + annuaire de contacts)
typedef struct {
    cle_t cles[MAX_CLES];
    int nb_cles;
    contact_t contacts[MAX_CONTACTS];
    int nb_contacts;
} trousseau_t;

void init_trousseau(trousseau_t *t);
int  sauver_trousseau(const trousseau_t *t, const char *fichier, const char *mot_de_passe);
int  charger_trousseau(trousseau_t *t, const char *fichier, const char *mot_de_passe);
int  executer_commande(trousseau_t *t, char *ligne, FILE *entree);
void lancer_interprete(trousseau_t *t, FILE *entree);

#endif