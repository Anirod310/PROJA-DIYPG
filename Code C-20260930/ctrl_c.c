#include  <stdio.h>
#include  <signal.h>
#include  <stdlib.h>

int i;
void     INThandler(int);

int  main(void)
{
     signal(SIGINT, INThandler);
     i = 0;
     while (1){
          printf("i = %d\n",i);
          i++;
          getchar();}
     return 0;
}

void  INThandler(int sig)
{
     char  c;

     signal(sig, SIG_IGN);
     // actions...
     printf("arrêt avec i = %d\n",i);
     printf("OUCH, did you hit Ctrl-C?\n"
            "Do you really want to quit? [y/n] ");
     c = getchar();
     if (c == 'y' || c == 'Y'){
       // actions
       printf("sortie avec i = %d\n",i);
       exit(0);
     }
     else{
          printf("Je reprends avec i = %d\n",i);
          signal(SIGINT, INThandler);
        }

     getchar(); // Get new line character
}
