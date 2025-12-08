---
tags:
  - security
  - osint
  - reconnaissance
  - dorking
---

# OSINT (Open Source Intelligence)

L'OSINT consiste à collecter et analyser des informations disponibles publiquement pour construire une connaissance ciblée. Pour un SysAdmin/DevOps, c'est essentiel pour :

![OSINT Workflow](../assets/infographics/security/osint-workflow.jpeg)
*   **Sécurité Défensive** : Vérifier ce que votre infrastructure expose involontairement.
*   **Reconnaissance Attaquante** : Comprendre les techniques utilisées par les pirates.

## 1. Google Hacking (Google Dorks)

Utiliser des opérateurs de recherche avancés de Google pour trouver des informations cachées ou des vulnérabilités.

### Opérateurs Clés

| Opérateur | Description | Exemple |
|-----------|-------------|---------|
| `site:`   | Recherche sur un domaine spécifique. | `site:example.com admin login` |
| `intitle:`| Recherche un mot dans le titre de la page. | `intitle:"Index of" backups` |
| `inurl:`  | Recherche un mot dans l'URL. | `inurl:admin.php` |
| `filetype:`| Recherche un type de fichier spécifique. | `filetype:pdf "confidentiel"` |
| `intext:` | Recherche un mot dans le corps du texte. | `intext:"password" site:mycompany.com` |
| `cache:`  | Affiche la version en cache de la page. | `cache:example.com` |

### Exemples de Dorks Utiles

*   **Fichiers de configuration exposés** : `filetype:env intext:DB_PASSWORD`
*   **Index de répertoires** : `intitle:"Index of" /backup`
*   **Ports ouverts non sécurisés** : `inurl:8080 intitle:"Dashboard"`
*   **Fichiers log sensibles** : `filetype:log inurl:error "password"`

## 2. Shodan : Le Moteur de Recherche des Objets Connectés

Shodan scanne Internet et indexe les bannières des services exposés (Webcam, routeurs, serveurs, etc.). C'est un Google pour les "choses" connectées.

### Utilisation pour la Défense
*   Vérifier si vos propres serveurs exposent des ports inattendus ou des versions de logiciels vulnérables.
*   `hostname:yourcompany.com`
*   `port:22 country:FR` (Trouver les SSH exposés en France)
*   `webcam xp` (Recherche de webcams non sécurisées)

## 3. Recon-ng : Le Framework de Reconnaissance

Un outil CLI puissant pour automatiser la collecte d'informations. Il utilise des modules pour interroger diverses sources (DNS, Whois, réseaux sociaux).

### Workflow Typique
1.  `recon-ng`
2.  `add domains example.com`
3.  `use recon/domains-hosts/google_site_web` (Trouve les sous-domaines via Google)
4.  `run`
5.  `show hosts`

## 4. BBOT (Bighuge Bountiful OSINT Tool)

Le "nouveau venu" qui remplace souvent Recon-ng. Écrit en Python, il est extrêmement modulaire et rapide.

*   **Tout-en-un** : Subdomains, Port scan, Web screenshots, Cloud buckets.
*   **Récursif** : Si il trouve un sous-domaine, il le scanne aussi.

```bash
# Scan complet d'une cible
bbot -t example.com -f subdomain-enum

# Scan passif uniquement (sans toucher la cible)
bbot -t example.com -f passive
```

## 5. Metagoofil : La Chasse aux Métadonnées

Les documents publics (PDF, DOCX, XLSX) contiennent souvent des trésors : noms d'utilisateurs, chemins de serveurs, versions de logiciels.

```bash
# Télécharge les PDF de example.com et extrait les métadonnées
metagoofil -d example.com -t pdf -n 20 -o fichiers_pdf
```
*Résultat : Une liste de logins potentiels pour vos attaques Bruteforce.*

## 6. Maltego : La Cartographie Visuelle

Un outil graphique pour visualiser les liens entre différentes entités (personnes, emails, domaines, infrastructures). Très efficace pour les enquêtes complexes.

## 7. Mesures Préventives
*   **Hygiène Numérique** : Ne pas exposer d'informations sensibles (mots de passe dans le code, logs détaillés).
*   **Politique de Publication** : Contrôler ce qui est indexé par les moteurs de recherche (robots.txt, méta-tags).
*   **Surveillance Active** : Utiliser des outils d'OSINT sur ses propres ressources (comme un attaquant le ferait).
