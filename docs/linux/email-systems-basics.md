---
tags:
  - linux
  - email
  - smtp
  - postfix
  - imap
---

# Architecture & Services Email

Comprendre le fonctionnement de la messagerie électronique, de l'envoi à la réception.

## Composants d'un Système de Messagerie

Le trajet d'un email implique plusieurs acteurs spécialisés.

| Acronyme | Nom Complet | Rôle | Analogie "Poste" | Exemple |
|----------|-------------|------|------------------|---------|
| **MUA** | Mail User Agent | Client de messagerie utilisé par l'utilisateur pour lire/écrire. | La boîte aux lettres personnelle | Outlook, Thunderbird, Webmail (Gmail) |
| **MTA** | Mail Transfer Agent | Serveur qui route les emails d'un serveur à un autre via SMTP. | Le centre de tri postal | **Postfix**, Exim, Sendmail, Exchange |
| **MDA** | Mail Delivery Agent | Programme qui stocke le message dans la boîte locale de l'utilisateur. | Le facteur qui dépose le courrier | Dovecot, Procmail |

### Flux d'un Email

1.  **Envoi** : Le MUA (Thunderbird) envoie le mail au MTA local via **SMTP** (port 587).
2.  **Routage** : Le MTA interroge le DNS (enregistrement **MX**) pour trouver le serveur destinataire.
3.  **Transfert** : Le MTA expéditeur transmet le mail au MTA destinataire via **SMTP** (port 25).
4.  **Stockage** : Le MTA destinataire passe le mail au MDA qui l'écrit sur le disque (format *Maildir* ou *Mbox*).
5.  **Relève** : Le MUA destinataire récupère le mail via **IMAP** ou **POP**.

---

## Protocoles Standards

### SMTP (Simple Message Transfer Protocol)
Utilisé pour l'**envoi** et le **transfert** entre serveurs.
*   **Port 25** : Transfert serveur à serveur (MTA-to-MTA). Souvent bloqué par les FAI résidentiels.
*   **Port 587 (Submission)** : Envoi client à serveur (MUA-to-MTA) avec authentification (STARTTLS). Recommandé.
*   **Port 465** : Ancienne norme pour SMTP sur SSL (SMTPS), encore supportée.

### IMAP (Internet Message Access Protocol)
*   **Port 143** (non chiffré) / **993** (IMAPS).
*   **Fonctionnement** : Les mails restent sur le serveur. Synchronisation bidirectionnelle (lecture, dossiers, états).
*   **Usage** : Idéal pour accès multi-appareils (Smartphone + PC).

### POP3 (Post Office Protocol version 3)
*   **Port 110** (non chiffré) / **995** (POP3S).
*   **Fonctionnement** : Télécharge les mails et (souvent) les supprime du serveur.
*   **Usage** : Obsolète, sauf pour archivage local ou contrainte d'espace serveur.

---

## Délivrabilité & Sécurité

Pour éviter d'être classé comme SPAM, trois mécanismes DNS sont indispensables.

### 1. SPF (Sender Policy Framework)
Un enregistrement DNS `TXT` qui liste les IP autorisées à envoyer des emails pour votre domaine.
*   *Exemple* : `v=spf1 ip4:192.0.2.10 include:_spf.google.com ~all`
*   *Effet* : Empêche un tiers d'utiliser votre domaine pour envoyer des mails depuis une autre IP.

### 2. DKIM (DomainKeys Identified Mail)
Signature cryptographique ajoutée dans l'en-tête du mail.
*   Le serveur émetteur signe le mail avec sa **clé privée**.
*   Le serveur récepteur vérifie la signature avec la **clé publique** publiée dans le DNS.
*   *Effet* : Garantit que le mail n'a pas été altéré en transit.

### 3. DMARC (Domain-based Message Authentication, Reporting, and Conformance)
Une politique qui dit au récepteur quoi faire si SPF ou DKIM échouent.
*   *Exemple* : `v=DMARC1; p=reject; rua=mailto:admin@example.com`
*   *Effet* : Bloque les emails non authentifiés et envoie un rapport à l'admin.

---

## On-Premise vs SaaS (Cloud)

| Critère | Auto-hébergement (Postfix/Dovecot) | SaaS (Google Workspace, O365) |
|---------|------------------------------------|-------------------------------|
| **Confidentialité** | Totale (si bien géré) | Données chez un tiers (US Cloud Act) |
| **Coût** | Faible (VPS Linux) mais temps humain élevé | Abonnement mensuel par utilisateur |
| **Maintenance** | Critique (Mises à jour, Blacklists, Sécurité) | Gérée par le fournisseur |
| **Délivrabilité** | Difficile (IP reputation à construire) | Excellente par défaut |

### Quand s'auto-héberger ?
*   Pour apprendre (Projets pédagogiques).
*   Pour une confidentialité absolue (Journalistes, Avocats).
*   Pour des besoins d'envoi transactionnel massif spécifiques.
*   *Sinon, pour une entreprise standard, le SaaS est souvent plus pragmatique.*
