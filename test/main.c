/// \file main.c
/// \brief programme de test de la phase 1
/// Usage : ./phase1 demo [max]          genere et affiche une paire de clefs
///         ./phase1 tests [max]         lance tous les tests
///         ./phase1 overflow [essais]   bilan du depassement de capacite en fonction de MAX_PRIME
///         ./phase1 b64enc|b64dec|enc|dec ...   voir l'aide

#include "phase1.h"

FILE *logfp;

static void aide(const char *p){
    printf("Usage :\n"
           "  %s demo [max]\n  %s tests [max]\n  %s overflow [essais]\n"
           "  %s genkey <fichier_cles> [max]\n"
           "  %s enc <cles> <clair> <chiffre>\n  %s dec <cles> <chiffre> <clair>\n"
           "  %s b64enc <bin> <b64>\n  %s b64dec <b64> <bin>\n", p,p,p,p,p,p,p,p);
}

int main(int argc, char **argv){
    srand((unsigned)time(NULL));
    logfp = fopen("log.txt", "w");
    if (!logfp){ perror("log.txt"); return 1; }
    if (argc < 2){ aide(argv[0]); fclose(logfp); return 1; }

    const char *cmd = argv[1];
    int ret = 0;
    keyPair_t kp;

    if (!strcmp(cmd, "demo")){
        uint64_t maxp = (argc > 2) ? strtoull(argv[2], NULL, 10) : MAX_PRIME;
        genKeysRabin(&kp.pubKey, &kp.privKey, maxp);
        printKeyPair(kp);
        testChiffrementOverflow(maxp);
    }
    else if (!strcmp(cmd, "tests")){
        uint64_t maxp = (argc > 2) ? strtoull(argv[2], NULL, 10) : MAX_PRIME;
        ret = lancer_tous_les_tests(maxp) != 0;
    }
    else if (!strcmp(cmd, "overflow")){
        int essais = (argc > 2) ? atoi(argv[2]) : 30;
        const uint64_t paliers[] = {10000, 30000, 60000, 65000, 66000, 70000, 100000,
                                    1000000, 100000000ULL, 2000000000ULL};
        printf("Bilan du depassement (octets 0..255, %d paires par palier)\n", essais);
        for (size_t i = 0; i < sizeof paliers / sizeof *paliers; i++)
            bilanOverflow(paliers[i], essais);
    }
    else if (!strcmp(cmd, "genkey") && argc >= 3){
        uint64_t maxp = (argc > 3) ? strtoull(argv[3], NULL, 10) : MAX_PRIME;
        genKeysRabin(&kp.pubKey, &kp.privKey, maxp);
        printKeyPair(kp);
        ret = !saveKeytoFile(kp, argv[2]);
    }
    else if (!strcmp(cmd, "enc") && argc == 5){
        ret = !(loadKeytoprog(&kp, argv[2]) && chiffrer_fichier(argv[3], argv[4], kp.pubKey));
    }
    else if (!strcmp(cmd, "dec") && argc == 5){
        ret = !(loadKeytoprog(&kp, argv[2]) && dechiffrer_fichier(argv[3], argv[4], kp.privKey));
    }
    else if (!strcmp(cmd, "b64enc") && argc == 4) ret = !fichier_vers_base64(argv[2], argv[3]);
    else if (!strcmp(cmd, "b64dec") && argc == 4) ret = !base64_vers_fichier(argv[2], argv[3]);
    else { aide(argv[0]); ret = 1; }

    base64_cleanup();
    fclose(logfp);
    return ret;
}