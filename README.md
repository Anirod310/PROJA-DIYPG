# Projet DIYPG

Projet de l'UE « Projet Avancé » . Le but : recréer, en version simplifiée, un outil de chiffrement comme GPG, basé sur l'algorithme **RSA**.

**Équipe 7 :** Dorian Bousseksou (22108340), Clément Boillat (22103053), Ethan Napoletano (22204019), Tahar Mokhtari (22209563)

---

##  Phase 1

### Sommaire

1. [Petit résumé](#en-bref)
2. [Petit lexique](#lexique)
3. [Démarrer](#demarrer)
4. [Utiliser le programme](#utiliser)
5. [Partie 1.0 – Les clefs RSA](#partie-10)
6. [Partie 1.1 – Chiffrer des octets](#partie-11)
7. [Partie 1.2 – Chiffrer un fichier](#partie-12)
8. [Partie 1.3 – La conversion base64](#partie-13)
9. [Les tests](#tests)
10. [Problèmes trouvés dans le code fourni](#notes)
11. [Organisation des dossiers](#structure)
12. [Exemples d'affichage](#exemples)

---

<a id="en-bref"></a>
### Petit résumé

La phase 1 permet de :

- **fabriquer** une paire de clefs RSA (une publique, une privée) ;
- **chiffrer** un message ou un fichier avec la clef publique ;
- **déchiffrer** avec la clef privée pour retrouver le message d'origine ;
- **convertir** un fichier chiffré en texte lisible (base64) pour pouvoir l'envoyer par mail.

---

<a id="lexique"></a>
### Petit lexique

| Mot | Ce que ça veut dire |
|---|---|
| **Clair** | Le message avant chiffrement, lisible par tout le monde. |
| **Chiffré** | Le message après chiffrement, illisible sans la clef. |
| **Clef publique** | Sert à chiffrer. On peut la donner à n'importe qui. |
| **Clef privée** | Sert à déchiffrer. Elle reste secrète. |
| **N** | Un grand nombre, produit de deux nombres premiers p et q. Il fait partie des deux clefs. |
| **Octet** | Une petite case mémoire qui contient un nombre de 0 à 255. Une lettre = un octet (ou plusieurs pour les accents). |
| **Base64** | Une façon d'écrire des données quelconques avec des lettres et des chiffres seulement, pour les copier ou les envoyer par mail. |

**Principe de RSA en une ligne :** chaque nombre `m` du message devient `c = m^E mod N` (chiffrement), et on retrouve `m = c^U mod N` (déchiffrement).

---

<a id="demarrer"></a>
### Démarrer

Le projet est écrit en C et n'utilise aucune bibliothèque externe pour la phase 1.
Tous les import sont des imports de la bibliotheque C.


**Vérifier que tout marche :**

```bash
make clean && make
make test
```

La dernière ligne affichée doit être :
`===== TOUT EST OK (0 test(s) en echec) =====`

---

<a id="utiliser"></a>
### Utiliser le programme

Commandes disponibles (`max` est la valeur maximale des nombres premiers, 10000 par défaut) :

```bash
./bin/phase1 demo [max]                      # crée et affiche une paire de clefs
./bin/phase1 genkey cles.bin [max]           # crée une paire de clefs et la sauvegarde
./bin/phase1 enc cles.bin clair.txt msg.rsa  # chiffre un fichier
./bin/phase1 dec cles.bin msg.rsa clair.txt  # déchiffre un fichier
./bin/phase1 b64enc msg.rsa msg.b64          # fichier chiffré -> texte base64
./bin/phase1 b64dec msg.b64 msg.rsa          # texte base64 -> fichier chiffré
./bin/phase1 overflow [nb_paires]            # teste les limites de taille des clefs
./bin/phase1 tests [max]                     # lance les tests
```

**Commandes `make` :**

| Commande | Effet |
|---|---|
| `make` | compile le programme (`bin/phase1`) |
| `make test` | compile et lance les tests |
| `make overflow` | teste les limites de taille des clefs (30 paires par valeur) |
| `make sha_test` | lance le test SHA-256 fourni |
| `make ctrl_c` | compile la démo Ctrl-C fournie (pour la phase 3) |
| `make clean` | supprime les fichiers générés |
| `make help` | affiche cette liste |

---

<a id="partie-10"></a>
### Partie 1.0 – Les clefs RSA

### Ce qu'on a fait

- **Créer les clefs** (`genKeysSures`) : on choisit deux nombres premiers p et q différents, puis on calcule N = p × q et les deux exposants (E pour chiffrer, U pour déchiffrer).
- **Afficher les clefs** (`printKey`, `printKeyPair`) : E et N s'affichent en hexadécimal.
- **Sauvegarder / recharger** (`saveKeytoFile`, `loadKeytoprog`) : les clefs sont enregistrées dans un fichier. Au rechargement, on obtient une erreur si le fichier est absent ou incomplet.
- **Mesurer la limite de taille** (`testChiffrementOverflow`, `bilanOverflow`) : voir ci-dessous.

### Jusqu'à quelle taille de nombres premiers ça marche ? (MAX_PRIME)

`MAX_PRIME` est la valeur maximale des nombres premiers p et q. Dans le projet, elle vaut **10 000**.

**Le problème :** l'ordinateur calcule avec des nombres de 64 bits. Quand N est trop grand, une multiplication intermédiaire dépasse ce que 64 bits peuvent contenir, et le déchiffrement donne un mauvais résultat.

**Comment on a mesuré :** pour chaque valeur de `MAX_PRIME`, on crée 200 paires de clefs. Pour chaque paire, on chiffre puis on déchiffre les 256 valeurs d'octet possibles. Si un seul octet n'est pas retrouvé, la paire est « en échec ».

```bash
./bin/phase1 overflow 200
```

| MAX_PRIME | Paires testées | Paires en échec |
|---:|---:|---:|
| 1 000 | 200 | 0 |
| 10 000 | 200 | 0 |
| 60 000 | 200 | 0 |
| 65 536 | 200 | 0 |
| 70 000 | 200 | 2 |
| 100 000 | 200 | 47 |
| 1 000 000 | 200 | 195 |
| 100 000 000 | 200 | 200 |

*(Les clefs sont tirées au hasard : près de la limite, les chiffres changent un peu d'une exécution à l'autre.)*

**Ce qu'on observe :**

- Aucun échec jusqu'à 66 000, les premiers échecs apparaissent à 70 000.
- Le premier N en échec est 4 309 398 593, juste au-dessus de 4 294 967 296 (c'est 2³²).

**Pourquoi :** le calcul multiplie deux nombres plus petits que N. Le résultat tient dans 64 bits seulement si N ≤ 2³². Comme N = p × q, c'est garanti tant que p et q sont inférieurs à 65 536 (= 2¹⁶). Un peu au-dessus, ça marche encore parfois, car il faut que p **et** q soient tous les deux proches du maximum pour dépasser 2³².

**Valeur choisie : 10 000.** Elle est très en dessous de la limite. De plus, p et q sont au moins 17, donc N est toujours supérieur à 255 : un octet est toujours plus petit que N. Pour des clefs plus grandes, il faudra utiliser GMP (phase 2).

### Limites

- Les clefs sont limitées à N ≤ 2³² à cause des calculs sur 64 bits.
- Le fichier de clefs est une copie brute de la mémoire : il peut ne pas s'ouvrir correctement sur une autre machine.

### Démonstration

1. `make`
2. `./bin/phase1 demo` : crée et affiche une paire de clefs
3. `./bin/phase1 genkey cles.bin` : sauvegarde une paire
4. `./bin/phase1 overflow 200` : lance le bilan

---

<a id="partie-11"></a>
### Partie 1.1 – Chiffrer des octets

### Ce qu'on a fait

- **Chiffrer** (`chiffrer_octets`) : chaque octet `m` du message devient `c = m^E mod N`.
- **Stocker le résultat :** `c` peut dépasser 255, donc il ne tient pas dans un octet. On l'écrit sur **8 octets** (avec `u64_to_bytes`). Le chiffré est donc 8 fois plus long que le message.
- **Déchiffrer** (`dechiffrer_octets`) : on relit les octets par groupes de 8 (avec `bytes_to_u64`), puis on calcule `m = c^U mod N`. La fonction renvoie 0 si la longueur n'est pas un multiple de 8.

### Limites

- Ce n'est pas très sûr : un même octet donne toujours le même chiffré, ce qui permet de deviner le contenu en étudiant les répétitions (c'est annoncé dans le sujet, la phase 2 corrige ça).
- On utilise 8 octets par octet clair alors que 4 suffiraient pour N ≤ 2³². On a préféré ne pas dépendre de la taille de N.

### Démonstration

1. `make test`
2. Regarder la partie `--- chiffrement d'octets ---` : exemple du cours, `"Bonjour"`, caractères accentués, les 256 octets sur 20 paires de clefs.

---

<a id="partie-12"></a>
### Partie 1.2 – Chiffrer un fichier

### Ce qu'on a fait

- **Chiffrer** (`chiffrer_fichier`) : le fichier est lu octet par octet, et 8 octets chiffrés sont écrits pour chaque octet lu.
- **Déchiffrer** (`dechiffrer_fichier`) : le fichier chiffré est lu par blocs de 8 octets, et un octet est écrit pour chaque bloc.
- **Erreurs :** les deux fonctions renvoient 1 si tout s'est bien passé, 0 sinon (fichier introuvable, écriture impossible, fichier chiffré incomplet).

### Limites

- Le fichier chiffré est 8 fois plus gros que l'original.
- Même faiblesse que la partie 1.1 (un même octet donne toujours le même chiffré).

### Démonstration

1. Créer des clefs : `./bin/phase1 genkey cles.bin`
2. Créer un fichier : `echo "Bonjour !" > message.txt`
3. Chiffrer : `./bin/phase1 enc cles.bin message.txt message.rsa`
4. Déchiffrer : `./bin/phase1 dec cles.bin message.rsa message_dec.txt`
5. Comparer : `cmp message.txt message_dec.txt` (aucun message = les fichiers sont identiques)

---

<a id="partie-13"></a>
### Partie 1.3 – La conversion base64

Un fichier chiffré contient des octets quelconques, difficiles à copier ou à envoyer par mail. Le base64 les transforme en texte simple : 3 octets deviennent 4 caractères.

### Ce qu'on a fait

- **Fichier → base64** (`fichier_vers_base64`) : on lit tout le fichier, puis on l'encode.
- **Base64 → fichier** (`base64_vers_fichier`) : on enlève les retours à la ligne de fin de fichier (souvent ajoutés par un éditeur), puis on décode.
- **Vérification :** `echo -n 'Hi!' | base64` donne `SGkh`, comme notre programme.

### Limites

- Le décodage fourni ne repère pas les caractères invalides.
- Le fichier est chargé en entier en mémoire.

### Démonstration

1. Après la démonstration de la partie 1.2 : `./bin/phase1 b64enc message.rsa message.b64`
2. Afficher le résultat : `cat message.b64` (du texte lisible, prêt pour un mail)
3. Revenir au fichier chiffré : `./bin/phase1 b64dec message.b64 message2.rsa`
4. Déchiffrer : `./bin/phase1 dec cles.bin message2.rsa message_dec.txt`, puis comparer avec `message.txt`

---

<a id="tests"></a>
### Les tests

Les tests sont dans `test/tests.c`. On les lance avec `make test`. Chaque test affiche `[OK]` ou `[KO]`, puis un bilan.

### Notre façon de tester

- Vérifier des valeurs connues (exemple du cours : 4 → 31 → 4, et `"Hi!"` → `"SGkh"`).
- Chiffrer puis déchiffrer, et vérifier qu'on retrouve le message de départ.
- Tester les 256 valeurs d'octet et des caractères accentués.
- Répéter avec plusieurs paires de clefs, puisqu'elles sont tirées au hasard.
- Tester les cas d'erreur (fichier inexistant, fichier incomplet, longueur invalide).

### Ce qui est testé

| Partie | Tests |
|---|---|
| **Calculs** | nombres premiers (0, 2, 7, 8, 2047), pgcd, algorithme de Bézout, exemple du cours (4³ mod 33 = 31 et 31⁷ mod 33 = 4) |
| **Clefs** | même N pour les deux clefs, sauvegarde puis rechargement, fichier incomplet ou absent refusé, 50 paires avec p et q premiers et différents |
| **1.1** | exemple du cours, `'A'`, `"Bonjour"`, caractères accentués (2, 3 et 4 octets), les 256 octets sur 20 paires, taille du chiffré, longueur invalide refusée |
| **1.2** | fichier déchiffré identique à l'original, fichier incomplet refusé, fichier inexistant refusé |
| **1.3** | `"Hi!"`, `"f"`, décodage, nombres 32 et 64 bits, paire de clefs, fichier dans les deux sens |

### Ce qui n'est pas testé

- L'affichage des clefs (vérifié à l'œil avec `./bin/phase1 demo`)
- Le déchiffrement avec une mauvaise clef
- Le base64 avec des caractères invalides
- Les très gros fichiers et le disque plein

### Résultat

- **41 tests, 0 échec** avec `MAX_PRIME = 10 000`.
- Avec `./bin/phase1 tests 100000`, certains tests échouent : c'est normal, on dépasse la limite de 65 536.
- Vérification de la mémoire avec `valgrind` : aucune erreur, aucune fuite.
- Vérification avec `-fsanitize=address,undefined` : aucune erreur.

---

<a id="notes"></a>
### Problèmes trouvés dans le code fourni

En testant, on a trouvé quelques défauts dans le code donné par l'enseignant. On ne l'a pas modifié : on les contourne dans notre propre code.

| Problème | Notre solution |
|---|---|
| `genereUintRabin` laisse parfois passer des nombres qui ne sont pas premiers (2047, 3277, 4033…), ce qui donne des clefs fausses. | `genKeysSures` vérifie p et q avec `premier()`. |
| `genKeysRabin` arrête le programme si p = q. | `genKeysSures` tire un autre q dans ce cas. |
| Appeler `base64_cleanup` deux fois fait planter le programme. | On ne l'appelle qu'une fois, à la fin du `main`. |
| `base64_encode` ne marque pas la fin du texte. | On utilise toujours la longueur renvoyée. |
| `premier(1)` répond « premier ». | Sans effet : on ne l'appelle que sur des nombres ≥ 17. |

---

<a id="structure"></a>
### Organisation des dossiers

```
.
├── Makefile                  # commandes de compilation
├── README.md                 # ce fichier
├── src/                      # code source
│   ├── phase1.c              # notre code (parties 1.0 à 1.3)
│   ├── rsa_tools.c           # fourni : nombres premiers, calculs, clefs
│   ├── bezout.c              # fourni : calcul de l'inverse (Euclide étendu)
│   ├── int2char.c            # fourni : 4 octets <-> un nombre
│   ├── other_base64.c        # fourni : encodage / décodage base64
│   ├── sha256.c              # fourni : SHA-256 (phase 4)
│   ├── sha256_utils.c        # fourni : outils SHA-256
│   └── ctrl_c.c              # fourni : démo Ctrl-C (phase 3)
├── include/                  # fichiers d'en-tête (.h)
│   ├── phase1.h              # liste des fonctions de la phase 1
│   ├── rsa_common_header.h   # fourni : types et constantes (MAX_PRIME)
│   ├── sha256.h
│   ├── sha256_utils.h
│   └── bc_rsa.h              # fourni : blockchain (phase 5)
├── test/
│   ├── main.c                # programme principal (les commandes)
│   ├── tests.c               # tests de la phase 1
│   └── test_sha.c            # fourni : test SHA-256
├── build/                    # fichiers de compilation (généré)
└── bin/                      # programme compilé (généré)
```

**À savoir :** compilé avec GCC (`-Wall -Wextra`) sous Linux ; les avertissements restants viennent du code fourni. `make clean` supprime `build/`, `bin/`, `log.txt` et les fichiers de test.

---

<a id="exemples"></a>
### Exemples d'affichage

Les clefs sont tirées au hasard : les valeurs changent à chaque exécution.

**1) Créer une paire de clefs** (`./bin/phase1 demo`)

```console
Cle publique : E = 0x0000000000000005  N = 0x0000000002f32357
Cle privee   : E = 0x00000000025bee0d  N = 0x0000000002f32357
Test chiffrement ( avec MAX_PRIME = 10000) :
...
Tout est OK
```

**2) Chiffrer un fichier, puis le convertir en base64**

```console
$ ./bin/phase1 genkey cles.bin
$ ./bin/phase1 enc cles.bin message.txt message.rsa
$ ls -l message.txt message.rsa
10 message.txt
80 message.rsa
$ ./bin/phase1 b64enc message.rsa message.b64
$ cat message.b64
oaDmAAAAAACjiHQBAAAAAG11RAEAAAAA3r41AQAAAACjiHQBAAAAANjdDgAAAAAA7T8uAAAAAAAAAAACAAAAAKEoVQIAAAAAoIYBAAAAAAA=
```

*(10 octets au départ, 80 après chiffrement : c'est le « 8 fois plus gros ».)*

**3) Retrouver le message d'origine**

```console
$ ./bin/phase1 b64dec message.b64 message2.rsa
$ ./bin/phase1 dec cles.bin message2.rsa message_dec.txt
$ cat message_dec.txt
Bonjour !
```

**4) Limites de taille** (`./bin/phase1 overflow 200`)

```console
Bilan du depassement (octets 0..255, 200 paires par palier)
MAX_PRIME =        1000 :   0 / 200 paires de clefs en echec
MAX_PRIME =       65536 :   0 / 200 paires de clefs en echec
MAX_PRIME =       70000 :   2 / 200 paires de clefs en echec
MAX_PRIME =      100000 :  47 / 200 paires de clefs en echec
MAX_PRIME =   100000000 : 200 / 200 paires de clefs en echec
```

**5) Tests** (`make test`)

```console
===== TESTS PHASE 1 (max_prime = 10000) =====

--- maths ---
[OK] 7 est premier
[OK] 8 n'est pas premier
...
[OK] fichier base64 -> fichier ("Hi!")

===== TOUT EST OK (0 test(s) en echec) =====
```
