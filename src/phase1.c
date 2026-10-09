#include "phase1.h"



void printKey(rsaKey_t key, const char* keyName){

    
    printf("%016lx" PRIx64 "\n",key.E);
    printf("%016lx" PRIx64 "\n",key.N);



}

int saveKeytoFile(keyPair_t keyP, const char* filename){

    FILE* file = fopen(filename,"wb");
    if(file==NULL){
        printf("mauvais fich");
    }
    size_t written = fwrite(&keyP, sizeof(keyPair_t), 1, file);
    fclose(file);
    
    return written == 1; 
}

int loadKeytoprog(keyPair_t KeyP,const char* filename){
    
    FILE* file =fopen(filename,"rb");
        if(file==NULL){
            perror(file);
            return -1;
        }
    size_t read = fread(&KeyP, sizeof(keyPair_t), 1, file);
    fclose(file);

    return read==1;
    }



void testChiffrementOverflow(uint64_t max_prime_test) {
    keyPair_t kp;
    char msg_clair = 'A'; // Caractère UTF-8 de test
    uint64_t msg_int = (uint64_t)msg_clair;

    printf("\n=== TEST CHIFFREMENT (MAX_PRIME = %llu) ===\n", (unsigned long long)max_prime_test);

    // Boucle répétant le test sur 3 paires de clés différentes (Point 5)
    for (int i = 1; i <= 3; i++) {
        printf("--- Iteration %d ---\n", i);
        
        // 1. Génération d'une nouvelle paire de clés pour cette itération
        genKeysRabin(&kp.pubKey, &kp.privKey, max_prime_test);

        // 2. Chiffrement avec la clé publique : C = M^E mod N
        uint64_t chiffre = puissance_mod_n(msg_int, kp.pubKey.E, kp.pubKey.N);
        
        // 3. Déchiffrement avec la clé privée : M = C^D mod N
        uint64_t dechiffre = puissance_mod_n(chiffre, kp.privKey.E, kp.privKey.N);

        printf("Clair : '%c' (val: %llu) -> Chiffre : %llu -> Dechiffre : %llu ('%c')\n",
               msg_clair, (unsigned long long)msg_int, 
               (unsigned long long)chiffre, 
               (unsigned long long)dechiffre, (char)dechiffre);

        // 4. Vérification du résultat
        if (dechiffre == msg_int) {
            printf("[SUCCES] Le caractere a bien ete recupere.\n\n");
        } else {
            printf("[ECHEC] Depassement de capacite ! Le dechiffrement est faux.\n\n");
        }
    }
}




int chiffrer_fichier(const char *src, const char *dst, rsaKey_t pub){
    FILE *fi = fopen(src, "rb"); if (!fi){ perror(src); return 0; }
    FILE *fo = fopen(dst, "wb"); if (!fo){ perror(dst); fclose(fi); return 0; }
    int c; uint8_t buf[8];
    while ((c = fgetc(fi)) != EOF){
        u64_to_bytes(puissance_mod_n((uint64_t)c, pub.E, pub.N), buf);
        fwrite(buf, 1, 8, fo);
    }
    fclose(fi); fclose(fo);
    return 1;
}

int dechiffrer_fichier(const char *src, const char *dst, rsaKey_t priv){
    FILE *fi = fopen(src, "rb"); if (!fi){ perror(src); return 0; }
    FILE *fo = fopen(dst, "wb"); if (!fo){ perror(dst); fclose(fi); return 0; }
    uint8_t buf[8];
    while (fread(buf, 1, 8, fi) == 8)
        fputc((int)puissance_mod_n(bytes_to_u64(buf), priv.E, priv.N), fo);
    fclose(fi); fclose(fo);
    return 1;
}