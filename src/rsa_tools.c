/// \file rsa_tools.c
/// \author Vincent Dugat
/// \date summer 2019 update 2025
/// \brief calculs sur les nombres premiers, génération de clefs RSA

#include "../rsa_common_header.h"
#include "phase1.h"

void erreur(char* msg){
  printf("*** %s ***\n",msg);
  exit(-1);
}

uint64_t random_uint(uint64_t min,uint64_t max){
/// \brief génère un uint64_t aléatoire entre min et max
/// \param[in] min et max des uint64
/// \return n : min≤n≤max
  return (rand()%(max-min)) + min;
}

int premier (uint64_t n) {
/// \brief test de primarité, crible d'Erathostène
/// \returns 1 le nombre est premier, 0 sinon
  uint64_t d;

  if (n % 2 == 0)
    return (n == 2);
  for (d = 3; d * d <= n; d = d + 2)
    if (n % d == 0)
      return 0;
  return 1;
}

int decompose (uint64_t facteur[], uint64_t n){
  /// \brief décompose un entier en facteurs premiers
  /// \param[in] : n l'entier
  /// \pram[out] : facteur = tableau de facteurs
  /// \returns la dimension du tableau de facteurs.
  uint64_t d = 3;
  int i = 0;

  while (n % 2 == 0) {
    facteur[i++] = 2;
    n = n / 2;
  }
  while (d * d <= n)
    if (n % d == 0) {
      facteur[i++] = d;
      n = n / d;
    }
    else
      d = d + 2;
  if (n > 1)
    facteur[i++] = n;
  return i;
}

uint64_t puissance(uint64_t a, uint64_t e) {
  /// \brief puissance russe, une vieille connaissance
  /// \param[in] : a l'entier et e l'exposant
  /// \returns : a^e
  uint64_t p;

  for (p = 1; e > 0; e = e / 2) {
    if (e % 2 != 0)
      p = (p * a);
    a = (a * a);
  }
  return p;
}

uint64_t puissance_mod_n (uint64_t a, uint64_t e, uint64_t n) {
  /// \brief puissance modulaire, calcule a^e mod n
  /// \comment a*a peut dépasser la capacité d'un uint64_t
  /// \comment https://www.labri.fr/perso/betrema/deug/poly/exp-rapide.html
  /// \returns p = a^e mod n
  uint64_t p;
  for (p = 1; e > 0; e = e / 2) {
    if (e % 2 != 0)
      p = (p * a) % n;
    a = (a * a) % n;
  }
  return p;
}

uint64_t genereUint(uint64_t max,int *cpt){
  /// \brief génère un nombre premier inférieur à max avec Eratostène
  /// \param[in] max : la borne sup
  /// \param[out] cpt : nombre d'essais
  /// \returns : le nombre premier
  uint64_t num;
  *cpt=1;
  do{
    num = random_uint(17,max);
  } while (num%2!=1);

  while (!premier(num) && num<max){
    (*cpt)++;
    num=num+2;
  }
  if (num>=max)
    erreur("pb de génération de nombre premier (borne ?)\n");
  return num;
}

int rabin (uint64_t a, uint64_t n) {
  /// \brief test de Rabin sur la pimarité d'un entier
  /// \brief c'est un test statistique
  /// \returns 0 ou 1
  uint64_t p, e, m;
  int i, k;

  e = m = n - 1;
  for (k = 0; e % 2 == 0; k++)
    e = e / 2;

  p = puissance_mod_n (a, e, n);
  if (p == 1) return 1;

  for (i = 0; i < k; i++) {
    if (p == m) return 1;
    if (p == 1) return 0;
    p = (p * p) % n;
  }

  return 0;
}

int64_t genereUintRabin(uint64_t max,int *cpt){
  /// \brief fournit un nombre premier vérifié avec le test de rabin
  /// \returns le nombre premier < max
  uint64_t num;
  *cpt=1;
  int a=2;
  do{
    num = random_uint(17,max);
  } while (num%2!=1);
  while (!rabin(a,num) && num<max){
    (*cpt)++;
    num=num+2;
  }
  return num;
}

uint64_t pgcdFast(uint64_t a,uint64_t b){
  /// \brief pgcd rapide de a et b
  /// \param[in] a et b les deux entiers
  /// \returns pgcd(a,b)
  uint64_t pow2;
  // cas trivial ... PGCD(a,0)=a ou PGCD(0,b)=b
  // dans les deux cas : PGCD(a,b)=a+b si l'un des deux nombres est nul
  if(0==a || b==0) return a+b;
  // on s'occupe de toutes les puissances de deux contenues dans le PGCD(a,b)
  // PGCD( a=2^n.a' , b=2^n.b' )=2^n.PGCD(a',b')
  pow2 = 1u;
  while(!(a&1)) // tant que a est pair
    {
    if(!(b&1)) // si b est de plus pair
      {
      // PGCD( a=2.a' , b=2.b' )=2.PGCD(a',b')
      a     >>= 1;
      b     >>= 1;
      pow2  <<= 1;
      }
    else
      {
      // on rend <a> pair
      do a>>=1;while(!(a&1));
      break; // toutes les puissances de 2 du PGCD(a,b) ont ete traitees
      }
    }

  // on rend <b> pair
  while(!(b&1)) b>>=1;
  // ici les deux nombres sont pairs, le temps de calcul precedent est negligeable
  // devant ce qui suit...
  // information : la difference de deux nombres impairs est pair
  do
    {
    if(a==b)
      {
      break; // bingo ! PGCD(a,b)=a
      }
    else if(a > b)
      {
      a -= b; // PGCD(a,b)=PGCD(a-b,b)
      do a>>=1;while(!(a&1)); // on peut rendre <a> pair car on a plus de puissance de deux dans le PGCD
      }
    else // b > a
      {
      b -= a; // PGCD(a,b)=PGCD(a,b-a)
      do b>>=1;while(!(b&1)); // on peut rendre <b> pair car on a plus de puissance de deux dans le PGCD
      }
    }while(1);

return pow2*a;
} // pgcdFast()

void genKeysRabin(rsaKey_t *pubKey,rsaKey_t *privKey,uint64_t max_prime){
  /// \brief génère une paire de "grandes" clefs, adaptées au cryptage RSA par bloc
  /// \param[out] pubKey : clef publique
  /// \param[out] privKey : clef privée
printf(">>>Max=%llu\n",max_prime);
  int cpt1,cpt2;
  uint64_t num1 = genereUintRabin(max_prime,&cpt1);
  uint64_t num2 = genereUintRabin(max_prime,&cpt2);

  assert(num1 != num2);

  uint64_t N = num1*num2;
  uint64_t M = (num1-1)*(num2-1); //indicatrice d'Euler
  fprintf(logfp,"num1 = %llu num2 = %llu cpt1 = %d cpt2 = %d\n",num1,num2,cpt1,cpt2);
  uint64_t C = 2;

  // recherche d'un nombre premier avec M
  while (pgcdFast(C,M)!=1 && C<M){
    C++;
  }
  assert(C<M);// ça serait surprenant que ça échoue

  int64_t U,V;
  bezoutRSA(C,M,&U,&V);
  fprintf(logfp,"Retour de Bézout : U = %llu V = %llu C = %llu M = %llu\n",U,V,C,M);
  fprintf(logfp,"Calcul : C*U + M*V = %llu, C*U + M*V mod M = %llu\n",C*U + M*V,(C*U + M*V)%M);

  assert(2<U && U<M);

  pubKey->E = C;
  pubKey->N = N;
  privKey->E = U;
  privKey->N = N;
}

void inputKey(uint64_t E,uint64_t N,rsaKey_t *key){
  /// \brief pour debug : permet de saisir une clef
  /// \note ça peut servir... ou pas.
  printf("Entrez l'exposant : ");
  scanf("%llu",&E);
  printf("\nEntrez le modulo : ");
  scanf("%llu",&N);
  key->E = E;
  key->N = N;
}

void verifRabin(uint64_t max,int iterations){
  /// \brief vérifie la primarité des nombres premiers générés avec le test de Rabin
  /// \param[in] : le max pour la génération des nombres, le nombre d'itérations du test
  for (int i = 0;i<iterations;i++){
    int cpt = 0;
    uint64_t candidatPremier = genereUintRabin(max,&cpt);
    int res = premier(candidatPremier);
    printf("%llu ",candidatPremier);
    res == 0?printf("non premier\n"):printf("ok\n");
  }
}
