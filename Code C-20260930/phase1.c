#include "phase1.h"



void printKey(rsaKey_t key, const char* keyName){

    printf("%016" PRIx64 "\n",key.E);
    printf("%016" PRIx64 "\n",key.N);



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