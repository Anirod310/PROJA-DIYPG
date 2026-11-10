/// \file main_diypg.c
/// \brief Programme principal de l'application DIYPG (Phase 3)
#include "interprete.h"

FILE *logfp;

int main(void){
    srand((unsigned)time(NULL));
    logfp = stderr;

    static trousseau_t t;
    init_trousseau(&t);

    lancer_interprete(&t, stdin);
    base64_cleanup();
    return 0;
}