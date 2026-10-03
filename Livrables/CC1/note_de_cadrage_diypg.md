# Livrable 1 : Note de Cadrage et Plan de Développement

## Projet  : Do It Yourself Privacy Guard (DIYPG)

**Équipe projet :** Ethan NAPOLETANO, Dorian BOUSSEKSOU, Tahar MOKHTARI, Clément BOILAT  


## 1. Analyse et Objectif du Sujet

Le projet **DIYPG** consiste à créer en C une application de sécurité cryptographique inspirée du logiciel *Gnu Privacy Guard (GPG)*. L'objectif n'est pas simplement de reconstruire simplement des algos à partir des documents et codes fournis, mais de construire une solution complète et utilisable structurée autour de quatre piliers(détaillés dans le sujet):

* **Confidentialité :** Chiffrement de messages et fichiers via l'algorithme RSA.
* **Authenticité et Intégrité :** Calcul de hashage et signatures électroniques.
* **Ergonomie et Gestion :** Un interprète de commandes et un annuaire de clefs.
* **Confiance décentralisée :** Une Blockchain simulant une autorité de certification pour garantir la validité des clés publiques.

---

## 2. Ce que nous allons programmer

### Phase 1 : Implementation RSA et Outils de Base
* **1.0 Arithmétique modulaire :** Implémentation du crible d'Ératosthène, du test de primarité, de l'algorithme d'Euclide étendu et génération de clés RSA sur 64 bits.
* **1.1 – 1.2 Chiffrement & Fichiers :** Chiffrement octet par octet puis lecture/écriture de messages dans des fichiers binaires.
* **1.3 Base64 & Analyse de capacité :** Encodage/décodage binaire/Base64. Analyse du dépassement de capacité des uint64_t selon la constante MAX_PRIME.

### Phase 2 : Chiffrement par Blocs et Bibliothèque GMP
* **Chiffrement par blocs :** Regroupement des octets par blocs de 4 octets avec conversion *little-endian*.
* **Intégration GMP :** Utilisation de la bibliothèque multiprécision GMP pour traiter les grandes puissances modulaires sans débordement de mémoire avec précision.
* **Échange de clés :** Procédure de transmission des clés publiques au format Base64 entre membres de l'équipe pour tester.

### Phase 3 : Interprète de Commandes et Annuaire de Contacts
* **Boucle REPL :** Shell interactif assurant la saisie et l'exécution des commandes utilisateur.
* **Gestion du trousseau (V1.1)**
* **Annuaire de contacts (V2.0) :** Gestion des identifiants et suppression/ajout sélective de clés.
* **Protection :** Sauvegarde chiffrée et protégée sur disque du fichier d'annuaire.

### Phase 4 : Signatures Numériques et Hachage
* **Empreinte numérique :** Calcul du digest SHA-256 d'un fichier (en clair ou chiffré).
* **Signature RSA :** Chiffrement du digest avec la clé privée de signature de l'émetteur.
* **Vérification d'authenticité :** Déchiffrement du digest avec la clé publique du signataire et comparaison avec l'empreinte recalculée.

### Phase 5 : Registre d'Authentification des Clés par Blockchain
* **Structure de données :** Blocs chaînés par hash SHA-256 et liste de transactions.
* **Arbre de Merkle :** Calcul de la racine de Merkle pour sceller les transactions de chaque bloc.
* **Proof of Work :** Algorithme de minage imposant un critère de zéros initiaux selon une difficulté paramétrable.
* **Tokens & Événements :** Gestion de comptes (100 tokens utilisateur, 1000 institution) et enregistrement des événements.
* **Contrôle d'intégrité :** Bilan complet vérifiant la continuité des hashs depuis le bloc Génésis.

---

## 3. Architecture Logicielle & Découpage Modulaire

Pour garantir la logique et la bonne gesiton de notre code, l'application est découpée en modules indépendants :

| Module (Fichiers) | Fonctions Principales | Bibliothèques |
| :--- | :--- | :--- |
| rsa_core.c / .h | Génération de clés RSA, Miller-Rabin, Bézout, blocs de 4 octets et calculs GMP. | stdint.h, gmp.h |
| other_base64.c / .h | Encodage et décodage Base64 pour tampons mémoire et fichiers. | stdlib.h |
| keyring.c / .h | Gestion du trousseau personnel, annuaire V1/V2 et sauvegarde chiffrée. | rsa_core.h |
| sha256_sign.c / .h | Calcul des digests SHA-256, signature d'empreintes et vérification. | sha256.h |
| blockchain.c / .h | Structures de blocs/transactions (bc_rsa.h), Arbre de Merkle, minage PoW et audit. | sha256.h |
| cli_interpreter.c / .h | Boucle REPL, parsing de la ligne de commande et appel des sous-systèmes. | Tous les modules |
| Makefile | Automatisation de la compilation du projet et gestion des dépendances. | Make |
| README.md | Documentation du projet, manuel d'utilisation du Shell CLI et bilan des tests d'overflow sur MAX_PRIME. | Markdown |

---

## 4. Répartition des Tâches entre Étudiants

Chaque membre de l'équipe prend en charge un module principal tout en participant aux phases d'intégration :

| Étudiant | Rôle Majeur | Modules & Tâches Attribuées |
| :--- | :--- | :--- |
| **Dorian BOUSSEKSOU** | Lead CLI, Annuaire & REPL | Développement du Shell CLI (`cli_interpreter.c`, `main.c`), gestion du trousseau V1.1/V2.0 (`keyring.c`), sauvegarde chiffrée, `Makefile` et `README`. |
| **Ethan NAPOLETANO** | Lead Cœur RSA & GMP | Arithmétique RSA (Miller-Rabin, Bézout), découpage par blocs de 4 octets (`int2char.c`), intégration de la bibliothèque GMP et analyse d'overflow `MAX_PRIME`. |
| **Tahar MOKHTARI** | Signatures & Base64 | Module de conversion Base64 (`other_base64.c`), intégration du hachage SHA-256, développement de `signtext` / `verifysign` et commandes CLI de signature. |
| **Clément BOILAT** | Lead Blockchain & Certification | Structures de la chaîne (`bc_rsa.h`), calcul de la racine de Merkle, moteur de minage PoW, gestion des tokens, événements `NCK`/`RCK` et fonction d'audit. |

---

## 5. Échéancier Prévisionnel & Jalons de Contrôle Continu

Le calendrier de réalisation s'étend de septembre à décembre 2026 et s'articule autour des 4 évaluations du projet :

| Période | Phase du Projet | Objectifs Techniques & Livrables | Jalon & Note |
| :--- | :--- | :--- | :--- |
| Semaines 1 – 2 *(Septembre)* | Cadrage & Phase 1.0–1.2 | Dépôt Git, Makefile, fonctions RSA basiques (Bézout, Miller-Rabin), chiffrement octet par octet. | **CC1 (10%)**<br>Note de cadrage |
| Semaines 3 – 4 *(Octobre)* | Phase 1.3 & Phase 2 (GMP) | Conversion Base64, chiffrement par blocs de 4 octets avec GMP, échange de clés publiques. | Validation P1/P2 |
| Semaines 5 – 7 *(Fin Octobre)* | Phase 3 (CLI & Annuaire) | Shell interactif REPL, gestion du trousseau V1.1 et des contacts V2.0, sauvegarde chiffrée. | **CC2 (20%)**<br>**CC3 (20%)** |
| Semaines 8 – 10 *(Novembre)* | Phases 4 & 5 (Blockchain) | Hachage SHA-256, signatures, structures Blockchain, Merkle Tree, minage PoW et événements. | Intégration globale |
| Semaines 11 – 12 *(Décembre)* | Recette & Démonstration | Analyse mémoire avec Valgrind, finalisation du README, recette du logiciel et soutenance orale. | **CC4 (50%)**<br>Présentation finale |

---

## 6. Analyse des Risques Identifiés & Plan de Parades

| Risque Identifié | Impact Potentiel | Stratégie de Parade Étudiante |
| :--- | :--- | :--- |
| **Dépassement de capacité (uint64)** | Calculs erronés lors de l'exponentiation modulaire en Phase 1. | Tests rigoureux sur la constante `MAX_PRIME` et bascule systématique vers GMP en Phase 2. |
| **Fuites mémoire (Pointeurs C)** | Instabilité lors de la manipulation des listes chaînées ou d'objets GMP. | Implémentation de fonctions `free_*` systématiques et passage au crible de Valgrind à chaque phase. |
| **Erreurs de compilation GMP** | Échec de construction du projet sur l'environnement d'évaluation. | Rédaction d'un `Makefile` universel incluant explicitement l'option `-lgmp` et documentation README. |
| **Incohérence Blockchain** | Rupture du chaînage ou du Merkle Tree lors de l'ajout de blocs. | Développement d'une fonction d'audit automatisée vérifiant la chaîne depuis le bloc Génésis. |

