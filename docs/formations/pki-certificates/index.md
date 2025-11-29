---
tags:
  - formation
  - pki
  - certificats
  - security
  - openssl
  - secnumcloud
---

# PKI & Certificats : Maîtriser l'Infrastructure de Confiance

## Introduction

> **"Sans PKI, pas de confiance numérique."**

La **PKI (Public Key Infrastructure)** est le socle de la sécurité moderne : HTTPS, signatures électroniques, authentification forte, chiffrement E2E... Tout repose sur les certificats X.509 et la chaîne de confiance.

**Pourquoi maîtriser la PKI ?**

| Problème courant | Impact | Solution PKI |
|------------------|--------|--------------|
| Certificat expiré en production | Downtime, perte de confiance | Gestion du cycle de vie automatisée |
| "Not Secure" dans le navigateur | Image dégradée, SEO impacté | Certificats valides + chaîne complète |
| Attaque Man-in-the-Middle | Données interceptées | Certificate Pinning, mTLS |
| Audit SecNumCloud échoué | Non-conformité réglementaire | PKI interne + CRL/OCSP |
| Secrets dans le code | Fuite de credentials | Certificats client + Vault |

---

## Objectifs de la Formation

À la fin de cette formation, vous serez capable de :

1. **Comprendre** les concepts cryptographiques (symétrique, asymétrique, hashing)
2. **Maîtriser** le cycle de vie des certificats X.509 (génération, signature, révocation)
3. **Déployer** une PKI d'entreprise (CA Root, Sub-CA, templates)
4. **Automatiser** la gestion des certificats (ACME, certbot, PowerShell)
5. **Sécuriser** les infrastructures (mTLS, CRL interne, OCSP)
6. **Auditer** et maintenir la conformité (SecNumCloud, ANSSI)

---

## Public Cible

Cette formation s'adresse aux :

- **Administrateurs systèmes** gérant des certificats SSL/TLS
- **Security Engineers** responsables de la PKI d'entreprise
- **DevOps/SRE** automatisant les renouvellements de certificats
- **Architectes sécurité** concevant des infrastructures de confiance

**Niveau requis :** Intermédiaire (connaissances Linux/Windows, notions réseau TCP/IP)

---

## Programme

### Module 1 : Fondamentaux Cryptographiques (2h)

**Objectif :** Comprendre les bases théoriques avant la pratique.

**Contenu :**

- Les 3 piliers : Chiffrement, Hashing, Encodage
- Symétrique vs Asymétrique : quand utiliser quoi ?
- RSA, ECDSA, Ed25519 : comparaison des algorithmes
- Standards ANSSI : tailles de clés et algorithmes recommandés
- Vocabulaire : chiffrer ≠ crypter, clé publique vs privée

[:octicons-arrow-right-24: Accéder au Module 1](01-module.md)

---

### Module 2 : Certificats X.509 en Pratique (3h)

**Objectif :** Maîtriser le cycle de vie complet d'un certificat.

**Contenu :**

- Anatomie d'un certificat X.509 (Subject, Issuer, Extensions)
- Générer une clé privée et un CSR avec OpenSSL
- Formats de fichiers : PEM, DER, PFX/PKCS12, JKS
- Chaîne de confiance : Root CA → Intermediate → End-Entity
- Vérifier et debugger les certificats (openssl, certutil)
- Exercice : Créer un certificat auto-signé et le déployer sur Nginx

[:octicons-arrow-right-24: Accéder au Module 2](02-module.md)

---

### Module 3 : PKI d'Entreprise (4h)

**Objectif :** Déployer une infrastructure PKI complète.

**Contenu :**

- Architecture PKI : CA Root offline, Sub-CA online, RA
- Déployer une CA avec OpenSSL (Linux)
- Déployer une CA Microsoft AD CS (Windows Server)
- Templates de certificats : Web Server, Client Auth, Code Signing
- Révocation : CRL et OCSP
- Miroir CRL interne pour environnements isolés (SecNumCloud)
- Exercice : Créer une PKI 2-tiers avec CA Root et Sub-CA

[:octicons-arrow-right-24: Accéder au Module 3](03-module.md)

---

### Module 4 : Automatisation & DevOps (3h)

**Objectif :** Automatiser la gestion des certificats à grande échelle.

**Contenu :**

- Let's Encrypt et le protocole ACME
- Certbot : installation, plugins, renouvellement auto
- Ansible : déployer des certificats sur une flotte de serveurs
- HashiCorp Vault PKI : CA as a Service
- Monitoring : alerter avant expiration (Prometheus, scripts)
- mTLS : authentification mutuelle client/serveur
- Exercice : Automatiser le renouvellement sur 10 serveurs avec Ansible

[:octicons-arrow-right-24: Accéder au Module 4](04-module.md)

---

### Module 5 : TP Final - PKI SecNumCloud (4h)

**Objectif :** Mettre en pratique tous les concepts dans un scénario réel.

**Scénario :**

Vous êtes **Security Engineer** chez **CloudSecure**, un hébergeur qualifié SecNumCloud. Votre mission : déployer l'infrastructure PKI complète pour sécuriser les services internes.

**Tâches :**

1. Déployer une CA Root offline (air-gapped)
2. Créer une Sub-CA pour les certificats serveurs
3. Configurer un miroir CRL interne avec IIS
4. Émettre des certificats pour les services (Web, API, mTLS)
5. Automatiser le renouvellement avec Ansible
6. Documenter l'architecture et les procédures

**Livrables :**

- Scripts de déploiement (OpenSSL/PowerShell)
- Playbooks Ansible
- Documentation d'architecture
- Rapport de conformité ANSSI

[:octicons-arrow-right-24: Accéder au TP Final](05-tp-final.md)

---

## Durée Estimée

| Module | Durée | Type |
|--------|-------|------|
| Module 1 : Fondamentaux Crypto | 2h | Théorie + Quiz |
| Module 2 : Certificats X.509 | 3h | Pratique guidée |
| Module 3 : PKI Entreprise | 4h | Hands-on |
| Module 4 : Automatisation | 3h | DevOps |
| Module 5 : TP Final | 4h | Projet autonome |
| **Total** | **16h** | **Formation complète** |

!!! tip "Organisation Recommandée"
    **Format présentiel :** 2 jours (8h + 8h)

    **Format asynchrone :** 2-3 semaines à votre rythme

    **Environnement requis :** VM Linux + VM Windows Server (pour AD CS)

---

## Prérequis

!!! warning "Connaissances Nécessaires"
    Avant de commencer, assurez-vous de maîtriser :

    - ✅ **Linux** : Commandes de base, éditeur de texte, sudo
    - ✅ **Windows Server** : Installation de rôles, PowerShell basique
    - ✅ **Réseau** : TCP/IP, DNS, ports (443, 80, 8080)
    - ✅ **Web** : Notions HTTP/HTTPS, serveurs web (Nginx/Apache/IIS)

    **Ressources de préparation :**

    - [Guide Crypto Concepts ShellBook](../../security/crypto-concepts.md)
    - [Guide OpenSSL CLI ShellBook](../../security/openssl-cli.md)
    - [Guide Certificats ShellBook](../../security/certificates.md)

---

## Environnement Technique

### Matériel Recommandé

| Composant | Spécification | Raison |
|-----------|---------------|--------|
| **CPU** | 4 cores | VMs multiples |
| **RAM** | 16 GB minimum | 2-3 VMs simultanées |
| **Disque** | 100 GB SSD | VMs + snapshots |

### Logiciels Requis

| Logiciel | Version | Rôle |
|----------|---------|------|
| **VirtualBox/Hyper-V** | Dernière | Hyperviseur |
| **Rocky Linux 9** | 9.x | CA Linux, serveurs |
| **Windows Server 2022** | Eval | AD CS, PKI Microsoft |
| **OpenSSL** | 3.x | Opérations certificats |
| **Ansible** | 2.15+ | Automatisation |

---

## Compétences Acquises

À la fin de cette formation, vous serez capable de :

- ✅ Expliquer la différence entre chiffrement symétrique et asymétrique
- ✅ Générer des clés et certificats conformes aux standards ANSSI
- ✅ Déployer une PKI 2-tiers (Root CA + Sub-CA)
- ✅ Configurer la révocation (CRL, OCSP)
- ✅ Automatiser le cycle de vie des certificats
- ✅ Sécuriser les communications avec mTLS
- ✅ Auditer une infrastructure PKI existante

---

## Certification

Cette formation prépare aux certifications :

- **CompTIA Security+** : Domaine Cryptographie
- **CISSP** : Domaine 3 - Security Architecture
- **RHCSA/RHCE** : Gestion des certificats Linux
- **Microsoft AZ-800** : Windows Server Security

---

## Ressources Complémentaires

### Documentation Officielle

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Microsoft AD CS](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [ANSSI - Recommandations TLS](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-tls/)

### Guides ShellBook

- [Crypto Concepts](../../security/crypto-concepts.md) - Vocabulaire et théorie
- [OpenSSL CLI](../../security/openssl-cli.md) - Commandes essentielles
- [Certificats](../../security/certificates.md) - Cycle de vie et CRL

---

## Support

**Questions ou problèmes ?**

- [Discussions GitHub](https://github.com/VBlackJack/ShellBook/discussions)
- [Issues GitHub](https://github.com/VBlackJack/ShellBook/issues)

---

**Prêt ?** [:octicons-arrow-right-24: Commencer le Module 1](01-module.md){ .md-button .md-button--primary }
