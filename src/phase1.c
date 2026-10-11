/// \file phase1.c
/// \author Bousseksou Dorian, Boillat Clement, Napoletano Ethan, Mokhtari Tahar 
/// \brief phase 1 complete : fonctions 1.0, 1.1, 1.2, 1.3.
#include "phase1.h"


//Phase 1.0 :

/// genere un nombre premier < max_prime
/// le code fourni dans genereUintRabin renvoie parfois un nombre non premier (faux positif du test ou >= max_prime : on verifie donc le
/// resultat avec et on recommence tant qu'il n'est pas bon
static uint64_t generePremierSur(uint64_t max_prime){
    int cpt;
    uint64_t p = genereUintRabin(max_prime, &cpt);
    while (p >= max_prime || premier(p) == 0){
        p = genereUintRabin(max_prime, &cpt);
    }
    return p;
}

/// genere une paire de clefs RSA, comme le code fourni mais :
///  - p et q sont verifies et si q == p, on retire q au lieu d'arreter le programme avec assert(num1 != num2)
void genKeysSures(rsaKey_t *pubKey, rsaKey_t *privKey, uint64_t max_prime){
    //deux nombres premiers differents
    uint64_t p = generePremierSur(max_prime);
    uint64_t q = generePremierSur(max_prime);
    while (q == p){
        q = generePremierSur(max_prime);
    }

    uint64_t N = p * q;
    uint64_t M = (p - 1) * (q - 1);

    //exposant public C
    uint64_t C = 2;
    while (pgcdFast(C, M) != 1){
        C++;
    }

    //exposant prive U
    int64_t U, V;
    bezoutRSA(C, M, &U, &V);

    pubKey->E = C;
    pubKey->N = N;
    privKey->E = U;
    privKey->N = N;
}

//affichage de E etn N sur 16 bits
void printKey(rsaKey_t key, const char *keyName){
    printf("%s : E = 0x%016" PRIx64 "  N = 0x%016" PRIx64 "\n", keyName, key.E, key.N);
}

//affichage de la paire de clefs générées par genKeysRabin()
void printKeyPair(keyPair_t kp){
    printKey(kp.pubKey,  "Cle publique");
    printKey(kp.privKey, "Cle privee  ");
}

//sauvegarder une paire de cléfs dans le fichier filename 
int saveKeytoFile(keyPair_t keyP, const char *filename){
    FILE *f = fopen(filename, "wb");

    if (f == NULL){
        perror(filename);
        return 0;
    }

    size_t w = fwrite(&keyP, sizeof keyP, 1, f);

    fclose(f);
    return w == 1;// 1 = OK, 0 = echec
}

//charger la clef sauvegardée dans le fichier filename
int loadKeytoprog(keyPair_t *keyP, const char *filename){// pointeur pour recup l'adresse de la clefs entres les fonctions
    FILE *f = fopen(filename, "rb");

    if (f == NULL){
        perror(filename);
        return 0;
    }

    size_t r = fread(keyP, sizeof *keyP, 1, f);

    fclose(f);
    return r == 1;
}

/// Chiffre/dechiffre quelques octets (dont 'e acute' en UTF-8 = C3 A9) avec 3 paires de clefs.
/// \returns le nombre d'echecs
int testChiffrementOverflow(uint64_t max_prime_test){
    const uint64_t m = 'A';                  // le caractere A est en UTF-8 sur 1 octet
    int fails = 0;
    printf("Test chiffrement ( avec MAX_PRIME = %" PRIu64 ") : \n", max_prime_test);
    for (int i = 1; i <= 3; i++){            // on fait la boucle pour tester avec 3 paires de clefs !=
        keyPair_t kp;

        genKeysSures(&kp.pubKey, &kp.privKey, max_prime_test);
        printKeyPair(kp);

        uint64_t c = puissance_mod_n(m, kp.pubKey.E,  kp.pubKey.N);
        uint64_t d = puissance_mod_n(c, kp.privKey.E, kp.privKey.N);

        if (d != m){
            printf("[Echec] Message initial : %" PRIu64 " Message chiffré : %" PRIu64 " Message déchifré : %" PRIu64 "\n", m, c, d);
            fails++;
        }
    }
    printf(fails ? "%d echecs\n" : "Tout est OK\n", fails);
    return fails;
}

/// Pour une valeur de max_prime : pour essais paires de clefs, teste les 256 octets.
/// \returns le nombre de paires de clefs pour lesquelles au moins un octet est mal dechiffre
int bilanOverflow(uint64_t max_prime_test, int essais){
    int paires_ko = 0; //init compteur

    //Générer les paires de clés
    for (int t = 0; t < essais; t++){
        keyPair_t kp; 
        genKeysSures(&kp.pubKey, &kp.privKey, max_prime_test);

        //Tester les 256 octets
        int ko = 0;
        for (uint64_t m = 0; m < 256 && !ko; m++){

            //Chiffrer puis déchiffrer
            uint64_t c = puissance_mod_n(m, kp.pubKey.E,  kp.pubKey.N);
            uint64_t d = puissance_mod_n(c, kp.privKey.E, kp.privKey.N);
            if (d != m)ko = 1;   //Détecter les erreurs
        }
        paires_ko += ko;
    }
    //Affichage
    printf("MAX_PRIME = %12" PRIu64 " : %3d / %d paires de clefs en echec\n", max_prime_test, paires_ko, essais);
    return paires_ko;
}


//Phase 1.1 : chiffrement d'un tableau d'octets
//On stocke le resultat du chiffrement sur 8 octets (little endian).


/// découpe un nombre de 64 bits en 8 octets
void u64_to_bytes(uint64_t v, uint8_t *b) {
    for (int i = 0; i < 8; i++) {
        b[i] = v % 256;// le reste = le dernier octet de v
        v = v / 256; // on enlève ce dernier octet
    }
}

//recolle 8 octets en un nombre de 64 bits
uint64_t bytes_to_u64(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = v * 256 + b[i];// on décale v d'un octet et on ajoute b[i]
    }
    return v;
}

/// \returns nombre d'octets ecrits
size_t chiffrer_octets(const uint8_t *clair, size_t nb_octets_clairs,
                       rsaKey_t clePublique, uint8_t *chiffre){

    uint64_t E = clePublique.E;      // exposant de chiffrement
    uint64_t N = clePublique.N;      // module

    for (size_t i = 0; i < nb_octets_clairs; i++){
        uint64_t M = clair[i];                         // le message de base
        uint64_t C = puissance_mod_n(M, E, N);         // le chiffre
        u64_to_bytes(C, &chiffre[i * 8]);              // le bloc i va occuper les cases 8i à 8i+7
    }
    return nb_octets_clairs * 8;                       // 8 octets chiffres pour chaque octet clair
}

/// \returns nombre d'octets clairs ou 0 si c pas un mulktiplie de 8
size_t dechiffrer_octets(const uint8_t *chiffre, size_t nb_octets_chiffres,
                         rsaKey_t clePrivee, uint8_t *clair){
    if (nb_octets_chiffres % 8 != 0){                   // un chiffre valide fait toujours un multiple de 8 octets
        return 0;
    }
    uint64_t D = clePrivee.E;        // exposant de dechiffrement
    uint64_t N = clePrivee.N;        // module
    size_t nb_octets_clairs = nb_octets_chiffres / 8;   // 8 octets chiffres = 1 octet clair (l'inverse du dessus)

    for (size_t i = 0; i < nb_octets_clairs; i++){
        uint64_t C = bytes_to_u64(&chiffre[i * 8]);    // on relit le chiffre dans le bloc numero i
        uint64_t M = puissance_mod_n(C, D, N);         // le message
        clair[i] = (uint8_t)M;                         // retour a un octet
    }
    return nb_octets_clairs;
}


//Phase 1.2


/// chiffre le fichier src et écrit le résultat dans dst
/// renvoie 1 si tout s'est bien passé, 0 en cas d'erreur
int chiffrer_fichier(const char *src, const char *dst, rsaKey_t pub) {
    //ouvrir le fichier à lire
    FILE *fi = fopen(src, "rb");
    if (fi == NULL) {
        perror(src);
        return 0;
    }

    //ouvrir le fichier à écrire
    FILE *fo = fopen(dst, "wb");
    if (fo == NULL) {
        perror(dst);
        fclose(fi);// on referme celui qui était déjà ouvert
        return 0;
    }

    uint8_t buf[8];
    int c = fgetc(fi);           // lire le premier octet
    while (c != EOF) {           // tant qu'on n'est pas à la fin du fichier
        //chiffrer l'octet
        uint64_t chiffre = puissance_mod_n(c, pub.E, pub.N);
        //decoup le chiffré en 8 octets et les écrire
        u64_to_bytes(chiffre, buf);
        size_t nbEcrits = fwrite(buf, 1, 8, fo);
        if (nbEcrits != 8) {     // disque plein, par exemple
            perror(dst);
            fclose(fi);
            fclose(fo);
            return 0;
        }
        c = fgetc(fi);// lire l'octet suivant
    }

    //fermer les deux fichiers
    fclose(fi);
    if (fclose(fo) != 0) {//test de la fermeture
        perror(dst);
        return 0;
    }
    return 1;
}


/// déchiffre le fichier src et écrit le résultat dans dst
/// renvoie 1 si tout s'est bien passé, 0 en cas d'erreur
int dechiffrer_fichier(const char *src, const char *dst, rsaKey_t priv) {
    FILE *fi = fopen(src, "rb");
    if (fi == NULL) {
        perror(src);
        return 0;
    }
    FILE *fo = fopen(dst, "wb");
    if (fo == NULL) {
        perror(dst);
        fclose(fi);
        return 0;
    }

    uint8_t buf[8];
    size_t nbLus = fread(buf, 1, 8, fi);   // lire le premier bloc
    while (nbLus == 8) {                   // tant qu'on a pu lire un bloc complet
        //recoller les 8 octets en un nombre
        uint64_t chiffre = bytes_to_u64(buf);
        //déchiffrer
        uint64_t clair = puissance_mod_n(chiffre, priv.E, priv.N);
        //clair < 256 alors il tient dans un octet, on l'écrit
        fputc(clair, fo);
        nbLus = fread(buf, 1, 8, fi);      // lire le bloc suivant
    }

    fclose(fi);
    if (fclose(fo) != 0) {
        perror(dst);
        return 0;
    }

    // s'il reste un bloc incomplet, le fichier chiffre est tronque ou abime donc on le précise
    if (nbLus != 0) {
        fprintf(stderr, "%s : fichier tronque (taille non multiple de 8)\n", src);
        return 0;
    }
    return 1;

    return 1;
}


//Phase 1.3

/// Permet de recuperer la taille et le contenu du fichier pour les fonctions d'après (fichier_vers_base64 et base64_vers_fichier)
/// \returns buffer avec le contenu lu
static unsigned char* lire_tout(const char *nom, size_t *len){
    //Ouvrir le fichier
    FILE *f = fopen(nom, "rb");
    if (!f) {
        perror(nom);
        return NULL;
    }
    fseek(f, 0, SEEK_END);   //place le curseur à la fin du fichier
    long taille = ftell(f);   //taille du fichier en octets
    rewind(f);      //replace le curseur au début du fichier

//Vérifier la taille
    if (taille< 0) {
        fclose(f);
        return NULL;
    }

    unsigned char *buf = malloc(taille > 0 ? (size_t)taille : 1);   //Réserver de la mémoire

    if (!buf) {
        fclose(f);
        return NULL;
    }

//Lire le contenu
    *len = fread(buf, 1, (size_t)taille, f);
    fclose(f);

    return buf;
}

/// convertit un fichier binaire (src) en un fichier texte base64 (dst)
/// renvoie 1 si tout s'est bien passé, 0 en cas d'erreur
int fichier_vers_base64(const char *src, const char *dst) {
    // 1. lire tout le fichier binaire en mémoire
    size_t lgBinaire;
    unsigned char *binaire = lire_tout(src, &lgBinaire);
    if (binaire == NULL) {
        return 0;
    }

    // 2. encoder en base64
    size_t lgTexte;
    char *texte = base64_encode(binaire, lgBinaire, &lgTexte);
    free(binaire);              
    if (texte == NULL) {
        return 0;
    }

    // 3. écrire le texte dans le fichier de sortie
    FILE *fo = fopen(dst, "w"); 
    if (fo == NULL) {
        perror(dst);
        free(texte);
        return 0;
    }
    fwrite(texte, 1, lgTexte, fo);
    free(texte);

    if (fclose(fo) != 0) {
        perror(dst);
        return 0;
    }
    return 1;
}

/// convertit un fichier texte base64 src en fichier binaire dst
/// renvoie 1 si tout s'est bien passé, 0 en cas d'erreur
int base64_vers_fichier(const char *src, const char *dst) {
    // 1. lire tout le fichier texte en mémoire
    size_t lgTexte;
    unsigned char *texte = lire_tout(src, &lgTexte);
    if (texte == NULL) {
        return 0;
    }

    // 2. enlever les retours à la ligne à la fin au cas ou
    while (lgTexte > 0) {
        unsigned char dernier = texte[lgTexte - 1];
        if (dernier == '\n' || dernier == '\r') {
            lgTexte = lgTexte - 1;  // on raccourcit d'un caractère pour l'enlever
        } else {
            break;             
        }
    }

    // 3. décoder
    size_t lgBinaire;
    unsigned char *binaire = base64_decode((char *)texte, lgTexte, &lgBinaire);
    free(texte);
    if (binaire == NULL) { // texte invalide
        return 0;
    }

    // 4. écrire les octets dans le fichier de sortie
    FILE *fo = fopen(dst, "wb"); 
    if (fo == NULL) {
        perror(dst);
        free(binaire);
        return 0;
    }
    fwrite(binaire, 1, lgBinaire, fo);
    free(binaire);

    if (fclose(fo) != 0) {
        perror(dst);
        return 0;
    }
    return 1;
}