# TP n°1 : Prise en main et analyse d'un incident — Abidjan Pharma

**Auteur :** DAHOUE MAMADOU
**Année académique :** 2026-2027
**Modules :** 1 et 2 (après CM1 et CM2)

---

## 📌 Introduction : Vocabulaire de base

Avant de commencer l'analyse, il est crucial de distinguer les concepts fondamentaux de la cybersécurité :
- **Menace** : Intention ou événement potentiel de nuire (ex: un pirate qui veut voler les données).
- **Attaque** : Concrétisation de la menace, action réelle (ex: défiguration du site, dépôt d'un webshell).
- **Vulnérabilité (facteur de risque)** : Faille ou faiblesse du système permettant à l'attaque de réussir (ex: méthode HTTP `PUT` activée, mot de passe faible).
- **Risque** : Combinaison de la probabilité qu'une menace exploite une vulnérabilité et de l'impact sur l'entreprise.

---

## 🛠️ Partie 1 — Prise en main du labo (en classe)

### A. Déploiement et vérification de l'isolement
- Déploiement des 3 conteneurs (`attaquant`, `cible-web`, `cible-ssh`) via Docker Compose. Vérification de leur état (`Up`).
- Test d'isolement réseau : `ping 8.8.8.8` depuis le conteneur attaquant. Résultat : `Network is unreachable`. Le labo est bien isolé d'Internet, conformément à la charte.

### B. Intégrité et contrôleur de fichiers (FIM)
- **Test manuel** : Calcul de l'empreinte SHA-256 du fichier `ordonnance.txt`. Ajout d'une ligne dans le fichier, puis recalcul de l'empreinte. L'empreinte a totalement changé, prouvant le principe de l'intégrité.
- **Script FIM** : Complétion du script `fim_a_completer.py`. Ajout d'une condition pour ignorer les fichiers `.log` (éviter les faux positifs) et ajout d'une alerte (`ALERTE : fichier ajoute`) lors de la détection d'un nouveau fichier.

### C. Chiffrement et signature avec OpenSSL
- **Chiffrement** : Chiffrement du fichier `ordonnance.txt` avec AES-256-CBC. Le fichier est devenu illisible (binaire). Déchiffrement réussi avec le mot de passe, prouvant la protection de la confidentialité.
- **Signature** : Génération d'une paire de clés RSA (privée/publique). Signature du fichier avec la clé privée. Vérification avec la clé publique : résultat `Verified OK`. L'authenticité et l'intégrité sont garanties.

### D. Faiblesse des mots de passe
- Tentative de cassage de la base `comptes_md5.txt` avec John the Ripper et un dictionnaire.
- **Note technique** : L'image Docker fournie contenait une version de John the Ripper ne supportant pas le format `raw-md5`, et Python n'était pas installé pour contourner le problème. Cette étape a néanmoins permis de comprendre la vulnérabilité des hachages faibles (MD5 sans sel) face aux attaques par dictionnaire.

---

## 🕵️‍♂️ Partie 2 — Analyse de l'incident d'Abidjan Pharma (à la maison)

### Travail 1 — Tableau de classification des attaques

| Attaque observée | Classe de menace | Facteur de risque | Risque (V×I, niveau) | Violation CID | Correction (sans implémenter) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Défiguration du site** (`PUT /index.html`) | Perturbation / Tromperie | Configuration serveur web trop permissive (méthode `PUT` activée) | Élevé | Intégrité | Désactiver la méthode `PUT` (TP5) |
| **Webshell déposé** (`/uploads/shell.php`) | Usurpation / Divulgation | Dossier `uploads` exécutable | Critique | Confidentialité, Intégrité, Disponibilité | Interdire l'exécution de scripts dans `/uploads` (TP5) |
| **Force brute SSH puis connexion réussie** | Usurpation | Politique de mot de passe faible, pas de blocage | Élevé | Confidentialité, Intégrité | Mots de passe forts + Fail2ban (TP4) |
| **Identifiant en clair sur HTTP** (pcap) | Divulgation | Utilisation de HTTP au lieu de HTTPS | Moyen | Confidentialité | Forcer HTTPS/TLS (TP5) |
| **Base de mots de passe MD5 exfiltrée** | Divulgation | Hachage faible (MD5 sans sel) | Critique | Confidentialité | Utiliser bcrypt/Argon2 (TP4) |
| **Données lisibles malgré AES-ECB** | Divulgation | Mode de chiffrement ECB non sécurisé | Élevé | Confidentialité | Utiliser AES-GCM ou AES-CBC avec IV (TP3) |

### Travail 2 — Violations CID justifiées par les traces

- **Défiguration** : Le fichier `/usr/share/nginx/html/index.html` a été écrasé par `<h1>Hacked by X</h1>`. Le log Nginx prouve la requête `PUT` par l'IP `196.49.52.17`. (Atteinte à l'**Intégrité**).
- **Webshell** : Le fichier `shell.php` contient `<?php system(...); ?>`. Les logs montrent l'exécution de `cat /etc/passwd`. L'attaquant peut lire, modifier ou détruire le système. (Atteinte à la **Confidentialité, l'Intégrité et la Disponibilité**).
- **Force brute SSH** : Le fichier `/incident/auth.log` montre de multiples `Failed password` suivis d'un `Accepted password for pharma`. L'attaquant a usurpé l'identité de l'utilisateur. (Atteinte à la **Confidentialité et l'Intégrité**).
- **Identifiant en clair** : Les logs Nginx et l'absence de TLS prouvent que les identifiants transitent en clair. (Atteinte à la **Confidentialité**).
- **MD5 et AES-ECB** : Les fichiers `comptes_md5.txt` et `donnees_chiffrees_ecb.bin` ont été récupérés. Le MD5 se casse facilement et l'ECB laisse apparaître des motifs. (Atteinte à la **Confidentialité**).

### Travail 3 — Corrections proposées (rattachées aux TP futurs)

- **Correction de la faille PUT** : Désactiver la méthode `PUT` dans Nginx. *Protège l'Intégrité. (TP5)*.
- **Correction du Webshell** : Interdire l'exécution PHP dans `/uploads`. *Protège la Confidentialité, l'Intégrité et la Disponibilité. (TP5)*.
- **Correction de la Force brute** : Politique de mots de passe complexes + `Fail2ban`. *Protège la Confidentialité et l'Intégrité. (TP4)*.
- **Correction du HTTP en clair** : Forcer HTTPS (TLS). *Protège la Confidentialité. (TP5)*.
- **Correction du MD5** : Remplacer par `bcrypt` ou `Argon2`. *Protège la Confidentialité. (TP4)*.
- **Correction de l'AES-ECB** : Remplacer par AES-GCM ou AES-CBC avec IV aléatoire. *Protège la Confidentialité. (TP3)*.

### Travail 4 — Priorisation

**Classement des risques (du plus grave au moins grave) :**
1. Webshell déposé (Critique)
2. Base de mots de passe MD5 exfiltrée (Critique)
3. Défiguration du site (Élevé)
4. Force brute SSH réussie (Élevé)
5. Données lisibles malgré AES-ECB (Élevé)
6. Identifiant en clair sur HTTP (Moyen)

**Paragraphe de priorisation :**
Abidjan Pharma doit commencer par corriger en urgence la vulnérabilité liée au **webshell** et au **dépôt de fichiers malveillants**. C'est la priorité absolue, car un webshell permet à un attaquant de rebondir sur le serveur, d'exfiltrer des données (comme la base MD5) et de porter atteinte aux trois propriétés de sécurité (Confidentialité, Intégrité, Disponibilité). La correction doit se concentrer sur la sécurisation du serveur web (désactivation des méthodes HTTP dangereuses comme PUT, interdiction d'exécution de scripts dans le dossier `/uploads`). Ensuite, la deuxième priorité est de sécuriser l'authentification : remplacer le hachage MD5 par un algorithme robuste (bcrypt) et mettre en place une politique de mots de passe forts avec un système de blocage (Fail2ban) pour empêcher les attaques par force brute. Ces actions sont à planifier pour les TP4 et TP5.

---
*Fin du compte rendu.*
