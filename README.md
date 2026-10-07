# DIYPG — Phase 1.0 : bilan


**Date :** <!-- jj/mm/aaaa -->


---

Compilation et execution de la phase : 
```bash
```

Fichiers du livrable : <!-- ex. rsa\_tools.c, bezout.c, rsa\_keys\_io.c, test\_phase1\_0.c, Makefile, README.md -->



---



## 1. Valeur de MAXPRIME



### 1.1 Son Role


MAXPRIME est définie dans rsa\_common\_header.h (valeur par défaut : 10000).

<!-- Préciser en une phrase son rôle exact dans votre code : borne supérieure des nombres premiers p et q générés ? -->



### 1.2 Méthode de mesure



- Nombre de paires de clefs générées par valeur de MAXPRIME : <!-- ex. 200 -->

- Pour chaque paire : chiffrement puis déchiffrement des 256 valeurs d'octet (0 à 255).

- MAXPRIME passée à la compilation avec -DMAXPRIME=<valeur>.

- Commandes utilisée :

```bash

for m in <liste des valeurs>; do

&#x20;   make clean

&#x20;   make test\_phase1\_0 CFLAGS="-Wall -Wextra -g -DMAXPRIME=$m"

&#x20;   ./test\_phase1\_0 200 | grep "^RESULT"

done

```



### 1.3 Résultats



| MAXPRIME | Paires testées | Octets testés | Échecs | Dépassement observé ? (oui/non) | Remarques |

|---------:|---------------:|--------------:|-------:|:-------------------------------:|-----------|

| 1 000 | | | | | |

| 10 000 (défaut) | | | | | |

| | | | | | |

| | | | | | |

| | | | | | |

| | | | | | |

| | | | | | |



### 1.4 Valeur limite trouvée



- Plus grande valeur de MAXPRIME sans dépassement : <!-- \_\_\_ -->

- Plus petite valeur de MAXPRIME avec dépassement : <!-- \_\_\_ -->

- Encadrement du seuil : <!-- \_\_\_ ≤ seuil < \_\_\_ -->

- Premier module N pour lequel un échec a été observé : <!-- \_\_\_ -->



### 1.5 Explication du dépassement



<!-- Expliquer où et pourquoi le dépassement de capacité des uint64 se produit

&#x20;    (quelle opération, quelle fonction, quelle grandeur dépasse 2^64 ?),

&#x20;    et comparer le seuil mesuré au seuil théorique. -->



### 1.6 Valeur retenue pour la suite du projet



**MAXPRIME = <!-- \_\_\_ -->**, car : <!-- justification -->



---



## 2. Exhaustivité des tests



### 2.1 Tests réalisés par rapport au cahier des charges



| Exigence du sujet | Test associé | Ce qui est vérifié | Résultat |

|-------------------|--------------|--------------------|----------|

| Affichage des clefs en hexadécimal | <!-- ex. T3 --> | <!-- --> | <!-- OK / KO / non testé --> |

| Génération et affichage d'une paire de clefs | <!-- ex. T2 --> | <!-- --> | |

| Sauvegarde / chargement d'une paire de clefs | <!-- ex. T4 --> | <!-- --> | |

| Chiffrement/déchiffrement d'un caractère UTF-8, boucle sur plusieurs paires | <!-- ex. T5 --> | <!-- --> | |

| Variation de MAXPRIME (dépassement uint64) | <!-- campagne §1 --> | <!-- --> | |



### 2.2 Étendue des données testées



| Dimension | Valeurs couvertes | Valeurs non couvertes |

|-----------|-------------------|-----------------------|

| Paires de clefs | <!-- nombre total générées : \_\_\_ --> | |

| Valeurs d'octet | <!-- ex. 0–255 toutes testées : oui / non --> | |

| Caractères UTF-8 | <!-- ex. ASCII, é (2 octets), € (3 octets) --> | |

| Valeurs de MAXPRIME | <!-- liste --> | |

| Exemple de référence du cours (33, 3) / (33, 7) | <!-- oui / non --> | |



### 2.3 Cas limites et cas d'erreur



| Cas | Testé ? | Comportement obtenu |

|-----|:-------:|---------------------|

| Module N ≤ 255 (octet ≥ N, chiffrement non injectif) | | |

| Fichier de clefs inexistant | | |

| Fichier de clefs corrompu / tronqué | | |

| Échec d'écriture du fichier de clefs | | |

| <!-- autre cas --> | | |



### 2.4 Ce qui n'est pas testé



<!-- Lister honnêtement les cas non couverts et la raison (temps, hors périmètre de la phase, etc.). -->



### 2.5 Conclusion sur l'exhaustivité



- Nombre total d'assertions exécutées : <!-- \_\_\_ --> — échecs : <!-- \_\_\_ --> — ignorées : <!-- \_\_\_ -->

- Outils complémentaires utilisés (le cas échéant) : <!-- valgrind, -fsanitize=address,undefined… -->

\- Appréciation globale : <!-- 2 à 3 phrases -->

