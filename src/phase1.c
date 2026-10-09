#include "phase1.h"


void printKeyHexa(rsaKey_t key, const char* keyName)
{   

    printf("Nom de la clé : %s\n", keyName);
    printf("Exposant de la clé : %016" PRIx64 "\n", key.E);
    printf("Modulo de la clé : %016" PRIx64 "\n", key.N);

}

int saveKeytoFile(keyPair_t keyP, const char* filename){

    FILE* file = fopen(filename,"wb");
    if(file==NULL){
        perror(file);
        return -1;
    }
    if((fwrite(&keyP, sizeof(keyPair_t), 1, file))==-1){
        perror(file);
        fclose(file);
        return -2;
    }

    return 1;
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
