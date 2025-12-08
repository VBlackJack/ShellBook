---
tags:
  - formation
  - security
  - hacking
  - pentest
  - red-team
---

# Formation Ethical Hacking Mastery (40h)

"Pour battre un hacker, il faut penser comme un hacker."
Cette formation intensive vous fait passer du côté offensif (**Red Team**) pour mieux comprendre comment sécuriser vos infrastructures.

## Objectifs Pédagogiques

*   🏴‍☠️ **Maîtriser** les outils standards (Kali Linux, Metasploit, Nmap, Burp).
*   🕵️ **Comprendre** la méthodologie d'un Pentest (Reconnaissance → Exploitation → Post-Exploitation).
*   🏢 **Attaquer** une infrastructure Active Directory (le cœur des entreprises).
*   🛡️ **Rédiger** un rapport d'audit professionnel.

## Public & Prérequis

*   **Public** : SysAdmins, DevOps, futurs Pentesters.
*   **Prérequis** : Solides bases Linux et Réseau (TCP/IP).
*   **Matériel** : Un PC capable de faire tourner 2-3 VMs (8-16 Go RAM).

---

## Programme Détaillé

### [Module 01 : Setup & Légalité](01-module.md)
*   **Cadre légal** : Ce qu'on a le droit de faire (et ne pas faire). Le contrat d'audit.
*   **Le Lab** : Installation de Kali Linux et de machines vulnérables (Metasploitable, DVWA).
*   **Anonymat** : VPN, Tor, Proxychains.

### [Module 02 : Reconnaissance & Réseau](02-module.md)
*   **Passive** : OSINT (Google Dorks, Shodan, TheHarvester).
*   **Active** : Scans Nmap (TCP/UDP), énumération de services.
*   **Exploitation** : Utilisation de Metasploit Framework pour lancer un exploit connu.

### [Module 03 : Web Hacking (OWASP)](03-module.md)
*   **Outils** : Burp Suite (Proxy d'interception).
*   **Injections** : SQL Injection (SQLi) manuelle et avec SQLmap.
*   **Client-Side** : XSS (Cross-Site Scripting).
*   **Bruteforce** : Hydra, Ffuf sur les formulaires et répertoires.

### [Module 04 : Active Directory & Windows](04-module.md)
*   **Concepts** : Kerberos, NTLM, LDAP.
*   **Outils** : Impacket, BloodHound, Mimikatz.
*   **Attaques** : LLMNR Poisoning, Kerberoasting, Pass-the-Hash.

### [Module 05 : Post-Exploitation](05-module.md)
*   **Privilege Escalation** : Passer de "www-data" à "root" (Linux) ou "System" (Windows).
*   **Pivoting** : Utiliser une machine compromise pour attaquer le réseau interne.
*   **Persistance** : Installer une backdoor discrète.

### [Module 06 : Projet Final (CTF Réaliste)](06-tp-final.md)
*   **Scénario** : Audit Black Box d'une entreprise fictive.
*   **Livrable** : Un rapport de pentest complet avec recommandations de correction.

---

## Ressources
*   [OSINT Cheat Sheet](../../security/osint.md)
*   [Digital Forensics](../../security/digital-forensics.md)
*   [Guide CTF](../../security/ctf-guide.md)
