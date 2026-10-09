/// \file phase1.c
/// \brief phase 1 : affichage/sauvegarde des clefs, chiffrement d'octets et de fichiers, base64
#include "phase1.h"

/* =====================================================================
 *  Phase 1.0 : affichage, sauvegarde, chargement des clefs, test de debordement
 * ===================================================================== */

void printKey(rsaKey_t key, const char *keyName){
    printf("%s : E = 0x%016" PRIx64 "  N = 0x%016" PRIx64 "\n", keyName, key.E, key.N);
}

void printKeyPair(keyPair_t kp){
    printKey(kp.pubKey,  "Cle publique");
    printKey(kp.privKey, "Cle privee  ");
}

int saveKeytoFile(keyPair_t keyP, const char *filename){
    FILE *f = fopen(filename, "wb");
    if (f == NULL){ perror(filename); return 0; }
    size_t w = fwrite(&keyP, sizeof keyP, 1, f);
    fclose(f);
    return w == 1;                       // 1 = OK, 0 = echec
}

int loadKeytoprog(keyPair_t *keyP, const char *filename){   // pointeur : la cle lue est conservee
    FILE *f = fopen(filename, "rb");
    if (f == NULL){ perror(filename); return 0; }
    size_t r = fread(keyP, sizeof *keyP, 1, f);
    fclose(f);
    return r == 1;
}

/// Chiffre/dechiffre quelques octets (dont 'e acute' en UTF-8 = C3 A9) avec 3 paires de clefs.
/// \returns le nombre d'echecs
int testChiffrementOverflow(uint64_t max_prime_test){
    const uint8_t msgs[] = { 'A', 0xC3, 0xA9, 0x00, 0xFF };
    int fails = 0;
    printf("\n=== TEST CHIFFREMENT (MAX_PRIME = %" PRIu64 ") ===\n", max_prime_test);
    for (int i = 1; i <= 3; i++){
        keyPair_t kp;
        genKeysRabin(&kp.pubKey, &kp.privKey, max_prime_test);
        printKeyPair(kp);
        for (size_t j = 0; j < sizeof msgs; j++){
            uint64_t m = msgs[j];
            uint64_t c = puissance_mod_n(m, kp.pubKey.E,  kp.pubKey.N);
            uint64_t d = puissance_mod_n(c, kp.privKey.E, kp.privKey.N);
            if (d != m){
                printf("[ECHEC] M=%" PRIu64 " C=%" PRIu64 " D=%" PRIu64 "\n", m, c, d);
                fails++;
            }
        }
    }
    printf(fails ? "=> %d echec(s)\n" : "=> tout OK\n", fails);
    return fails;
}

/// Pour une valeur de max_prime : sur `essais` paires de clefs, teste les 256 octets.
/// \returns le nombre de paires de clefs pour lesquelles au moins un octet est mal dechiffre
int bilanOverflow(uint64_t max_prime_test, int essais){
    int paires_ko = 0;
    for (int t = 0; t < essais; t++){
        keyPair_t kp;
        genKeysRabin(&kp.pubKey, &kp.privKey, max_prime_test);
        int ko = 0;
        for (uint64_t m = 0; m < 256 && !ko; m++){
            uint64_t c = puissance_mod_n(m, kp.pubKey.E,  kp.pubKey.N);
            uint64_t d = puissance_mod_n(c, kp.privKey.E, kp.privKey.N);
            if (d != m) ko = 1;
        }
        paires_ko += ko;
    }
    printf("MAX_PRIME = %12" PRIu64 " : %3d / %d paires de clefs en echec\n",
           max_prime_test, paires_ko, essais);
    return paires_ko;
}

/* =====================================================================
 *  Phase 1.1 : chiffrement d'un tableau d'octets
 *  Choix : chaque octet clair devient un chiffre C < N, stocke sur 8 octets (little endian).
 * ===================================================================== */

void u64_to_bytes(uint64_t v, uint8_t *b){
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)((v >> (8*i)) & 0xFF);
}

uint64_t bytes_to_u64(const uint8_t *b){
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}

/// \param out doit pouvoir contenir 8*len octets
/// \returns nombre d'octets ecrits (8*len)
size_t chiffrer_octets(const uint8_t *in, size_t len, rsaKey_t pub, uint8_t *out){
    for (size_t i = 0; i < len; i++)
        u64_to_bytes(puissance_mod_n(in[i], pub.E, pub.N), out + 8*i);
    return 8 * len;
}

/// \param out doit pouvoir contenir len/8 octets
/// \returns nombre d'octets clairs ecrits (len/8)
size_t dechiffrer_octets(const uint8_t *in, size_t len, rsaKey_t priv, uint8_t *out){
    size_t n = len / 8;
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)puissance_mod_n(bytes_to_u64(in + 8*i), priv.E, priv.N);
    return n;
}

/* =====================================================================
 *  Phase 1.2 : fichiers
 * ===================================================================== */

int chiffrer_fichier(const char *src, const char *dst, rsaKey_t pub){
    FILE *fi = fopen(src, "rb"); if (!fi){ perror(src); return 0; }
    FILE *fo = fopen(dst, "wb"); if (!fo){ perror(dst); fclose(fi); return 0; }
    int c; uint8_t buf[8];
    while ((c = fgetc(fi)) != EOF){
        u64_to_bytes(puissance_mod_n((uint64_t)c, pub.E, pub.N), buf);
        if (fwrite(buf, 1, 8, fo) != 8){ perror(dst); fclose(fi); fclose(fo); return 0; }
    }
    fclose(fi);
    return fclose(fo) == 0;
}

int dechiffrer_fichier(const char *src, const char *dst, rsaKey_t priv){
    FILE *fi = fopen(src, "rb"); if (!fi){ perror(src); return 0; }
    FILE *fo = fopen(dst, "wb"); if (!fo){ perror(dst); fclose(fi); return 0; }
    uint8_t buf[8];
    while (fread(buf, 1, 8, fi) == 8)
        fputc((int)puissance_mod_n(bytes_to_u64(buf), priv.E, priv.N), fo);
    fclose(fi);
    return fclose(fo) == 0;
}

/* =====================================================================
 *  Phase 1.3 : fichier <-> base64
 * ===================================================================== */

static unsigned char *lire_tout(const char *nom, size_t *len){
    FILE *f = fopen(nom, "rb"); if (!f){ perror(nom); return NULL; }
    fseek(f, 0, SEEK_END);
    long t = ftell(f);
    rewind(f);
    if (t < 0){ fclose(f); return NULL; }
    unsigned char *buf = malloc(t > 0 ? (size_t)t : 1);
    if (!buf){ fclose(f); return NULL; }
    *len = fread(buf, 1, (size_t)t, f);
    fclose(f);
    return buf;
}

int fichier_vers_base64(const char *src, const char *dst){
    size_t n, m;
    unsigned char *d = lire_tout(src, &n);
    if (!d) return 0;
    char *e = base64_encode(d, n, &m);
    free(d);
    if (!e) return 0;
    FILE *fo = fopen(dst, "w");
    if (!fo){ perror(dst); free(e); return 0; }
    fwrite(e, 1, m, fo);
    free(e);
    return fclose(fo) == 0;
}

int base64_vers_fichier(const char *src, const char *dst){
    size_t n, m;
    unsigned char *d = lire_tout(src, &n);
    if (!d) return 0;
    while (n > 0 && (d[n-1] == '\n' || d[n-1] == '\r')) n--;   // retire les fins de ligne
    unsigned char *b = base64_decode((char *)d, n, &m);
    free(d);
    if (!b) return 0;
    FILE *fo = fopen(dst, "wb");
    if (!fo){ perror(dst); free(b); return 0; }
    fwrite(b, 1, m, fo);
    free(b);
    return fclose(fo) == 0;
}