---
tags:
  - security
  - risk
  - management
---

# Gestion des Risques & Menaces

La sécurité informatique ne se limite pas aux outils techniques. Elle commence par une analyse rigoureuse des risques et des menaces qui pèsent sur le Système d'Information (SI).

## Les 3 Familles de Vulnérabilités

La sécurité est une chaîne dont la solidité dépend du maillon le plus faible.

### 1. Vulnérabilités Organisationnelles
Souvent négligées, elles concernent les processus humains :
*   **Méconnaissance des rôles** : Qui a accès à quoi ? (Cartographie des accès nécessaire).
*   **Absence de procédures** : Pas de plan de réaction en cas d'incident.
*   **Facteur Humain** : "La sécurité coûte cher et ne rapporte rien tant qu'elle ne sert pas."
*   **Solution** : Sensibilisation, formation, et adhésion des utilisateurs pour éviter le "syndrome du post-it avec mot de passe sur l'écran".

### 2. Vulnérabilités Physiques
L'accès direct au matériel contourne toutes les protections logicielles.
*   **Accès non contrôlé** : Baies de brassage ouvertes, datacenters accessibles.
*   **Sinistres** : Incendie, dégât des eaux, coupure électrique.
*   **Solution** : Contrôle d'accès (badges), redondance (RAID, double alimentation), sites de repli (PRA/PCA).

### 3. Vulnérabilités Technologiques
*   **Dette technique** : Logiciels obsolètes, OS non patchés.
*   **Empilement** : Complexité des couches applicatives générant des failles (interopérabilité).
*   **Configuration par défaut** : Utilisation de mots de passe ou règles par défaut.

---

## Le Processus de Gestion du Risque

Gérer le risque consiste à trouver l'équilibre entre le coût de la protection et le coût de l'impact.

1.  **Identification des actifs** : Que veut-on protéger ? (Données clients, secrets industriels, disponibilité du site web).
2.  **Identification des menaces** : Qui ou quoi peut nuire à ces actifs ?
3.  **Calcul du Risque** :
    $$ 	ext{Risque} = 	ext{Vulnérabilité} 	imes 	ext{Menace} 	imes 	ext{Impact} $$ 
4.  **Contre-mesures** : Évaluation du ROI des solutions proposées.

---

## Typologie des Attaquants

*   **Hackers "White Hat"** : Recherchent les failles pour les corriger (éthiques).
*   **Crackers "Black Hat"** : Cherchent à nuire, détruire ou voler par défi ou profit.
*   **Warez / Script Kiddies** : Cherchent des ressources (bande passante, stockage) pour leurs activités illégales.
*   **Menaces internes** : Employés mécontents, erreurs humaines (souvent la cause n°1).
*   **Espionnage industriel** : Concurrents cherchant à voler la propriété intellectuelle.

### La Technique des 5P (Jonathan Hogue)
Une attaque structurée suit souvent ce cycle :
1.  **Prospecter** : Reconnaissance (OSINT), ingénierie sociale, scan de ports.
2.  **Pénétrer** : Exploitation d'une faille pour entrer dans le réseau.
3.  **Perdurer** : Installation de backdoors pour maintenir l'accès.
4.  **Propager** : Mouvement latéral pour atteindre l'actif critique (Pivot).
5.  **Paralyser** : Destruction, chiffrement (Ransomware) ou vol de données, puis effacement des traces.

---

## Principales Attaques Réseau

| Attaque | Description | Contre-mesure |
|---------|-------------|---------------|
| **Sniffing** | Écoute passive du réseau pour voler des identifiants. | Chiffrement (HTTPS, SSH, VPN). |
| **Spoofing** | Usurpation d'identité (IP, ARP, DNS). | Authentification forte, DHCP Snooping, ARP Inspection. |
| **DoS / DDoS** | Saturation des ressources (Bande passante, CPU). | Rate limiting, Fail2Ban, WAF, CDN. |
| **Man-in-the-Middle** | Interception et modification des communications. | Certificats valides, HSTS. |
| **Social Engineering** | Manipulation psychologique des utilisateurs. | Formation, procédures de vérification. |
