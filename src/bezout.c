// Entrée : a, b entiers (naturels)
// Sortie : r entier (naturel) et  u, v entiers relatifs tels que r = pgcd(a, b) et r = a*u+b*v
//
// Initialisation : r := a, r' := b, u := 1, v := 0, u' := 0, v' := 1
// 								 q  quotient entier
// 								 rs, us, vs  variables de stockage intermédiaires
//
// les égalités r = a*u+b*v et r' = a*u'+b*v' sont des invariants de boucle
//
// tant que (r' ≠ 0) faire
// 	 q := r÷r'
// 	 rs := r, us := u, vs := v,
// 	 r := r', u := u', v := v',
// 	 r' := rs - q*r', u' = us - q*u', v' = vs - q*v'
// 	fait
// renvoyer (r, u, v)
#include "../rsa_common_header.h"
#include "phase1.h"
/// \brief
int64_t bezout(uint64_t a,uint64_t b,int64_t *u,int64_t *v){
/// \pre a, b entier naturels
/// \post r entier (naturel) et  u, v entiers relatifs tels que r = pgcd(a, b) et r = a*u+b*v mod b
/// \param[in] : a, b entiers (naturels)
/// \param[out] : u, v entiers relatifs tels que r = pgcd(a, b) et r = a*u+b*v mod b
/// \returns r entier
 	int64_t r = a;
	int64_t rp = b;
	int64_t up = 0;
	int64_t vp = 1;
	int64_t rs,vs,us,q;
 	*u = 1; *v = 0;
	assert(r == a*(*u)+b*(*v) && rp == a*up+b*vp);// invariant
	while (rp!=0){
    /// \invariant r = a*u+b*v et r' = a*u'+b*v'
    assert(r == a*(*u)+b*(*v) && rp == a*up+b*vp);// invariant
		q = r/rp;
		rs = r; us = *u; vs = *v;
		r = rp; *u = up; *v = vp;
		rp = rs - q*rp; up = us - q*up; vp = vs - q*vp;
	}
	return r;
}

int64_t bezoutRSA(uint64_t a,uint64_t b,int64_t *u,int64_t *v){
  /// \brief récupère (r,u,v) de Bézout. Si u est négatif on le remplace par
  /// \brief le premier qui est supérieur à 2
  /// returns u
  int64_t r = bezout(a,b,u,v);
  fprintf(logfp,"bezoutRSA : r = %llu U = %llu V = %llu\n",r,*u,*v);
  while (*u<=2){
    *u = *u+b;
  }
  return *u;
}
