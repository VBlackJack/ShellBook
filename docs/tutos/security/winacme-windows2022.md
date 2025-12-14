---
tags:
  - tutos
  - ssl
  - tls
  - letsencrypt
  - win-acme
  - windows
---

# Let's Encrypt avec win-acme sur Windows Server 2022

Certificats SSL/TLS gratuits pour **IIS** avec win-acme.

| Composant | Version |
|-----------|---------|
| Windows Server | 2022 |
| win-acme | 2.x |
| IIS | 10.0 |

**Durée estimée :** 20 minutes

---

## Prérequis

- Windows Server 2022 avec IIS installé
- Nom de domaine avec enregistrement A
- Ports 80 et 443 ouverts dans le firewall
- Site IIS configuré avec le bon hostname

---

## 1. Téléchargement de win-acme

```powershell
# Créer le dossier
New-Item -ItemType Directory -Path "C:\Tools\win-acme" -Force

# Télécharger la dernière version
$url = "https://github.com/win-acme/win-acme/releases/download/v2.2.9.1701/win-acme.v2.2.9.1701.x64.pluggable.zip"
$output = "C:\Tools\win-acme.zip"
Invoke-WebRequest -Uri $url -OutFile $output

# Extraire
Expand-Archive -Path $output -DestinationPath "C:\Tools\win-acme" -Force
Remove-Item $output
```

---

## 2. Configuration IIS préalable

### Vérifier le binding HTTP

```powershell
# Le site doit avoir un binding avec le hostname
Get-IISSite | ForEach-Object {
    $siteName = $_.Name
    $_.Bindings | ForEach-Object {
        [PSCustomObject]@{
            Site = $siteName
            Protocol = $_.Protocol
            BindingInfo = $_.BindingInformation
        }
    }
} | Format-Table -AutoSize
```

### Ajouter un binding si nécessaire

```powershell
# Ajouter binding HTTP avec hostname
New-IISSiteBinding -Name "Default Web Site" -BindingInformation "*:80:example.com" -Protocol http
```

---

## 3. Obtenir un certificat (interactif)

```powershell
# Lancer win-acme
cd C:\Tools\win-acme
.\wacs.exe
```

Menu interactif :
1. `N` - Create certificate (default settings)
2. Sélectionner le site IIS
3. Confirmer les domaines
4. Entrer une adresse email
5. Accepter les conditions

---

## 4. Mode ligne de commande (automatisé)

### Certificat simple

```powershell
cd C:\Tools\win-acme

# Certificat pour un site IIS
.\wacs.exe --target iis --siteid 1 --host example.com --installation iis --emailaddress admin@example.com --accepttos
```

### Plusieurs domaines

```powershell
.\wacs.exe --target iis --siteid 1 --host example.com,www.example.com --installation iis --emailaddress admin@example.com --accepttos
```

### Tous les bindings d'un site

```powershell
.\wacs.exe --target iis --siteid 1 --host-all-bindings --installation iis --emailaddress admin@example.com --accepttos
```

---

## 5. Paramètres utiles

```powershell
# Test (staging)
.\wacs.exe --target manual --host example.com --test --emailaddress admin@example.com --accepttos

# Validation HTTP (défaut)
.\wacs.exe --target manual --host example.com --validation filesystem --webroot "C:\inetpub\wwwroot" --emailaddress admin@example.com --accepttos

# Validation DNS manuelle
.\wacs.exe --target manual --host example.com --validation manual --emailaddress admin@example.com --accepttos

# Forcer le renouvellement
.\wacs.exe --renew --force
```

---

## 6. Emplacement des certificats

```powershell
# Certificats stockés dans
Get-ChildItem "C:\ProgramData\win-acme\acme-v02.api.letsencrypt.org\Certificates"

# Logs
Get-Content "C:\ProgramData\win-acme\acme-v02.api.letsencrypt.org\Log\log-*.txt" | Select-Object -Last 50
```

---

## 7. Configuration du binding HTTPS

win-acme configure automatiquement le binding HTTPS. Pour vérifier :

```powershell
# Voir tous les bindings SSL
Get-IISSite | ForEach-Object {
    $_.Bindings | Where-Object { $_.Protocol -eq "https" }
} | Format-Table

# Vérifier le certificat utilisé
Get-ChildItem Cert:\LocalMachine\WebHosting
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*example.com*" }
```

---

## 8. Renouvellement automatique

win-acme crée automatiquement une tâche planifiée.

```powershell
# Vérifier la tâche
Get-ScheduledTask | Where-Object { $_.TaskName -like "*win-acme*" }

# Détails
Get-ScheduledTask -TaskName "win-acme renew (acme-v02.api.letsencrypt.org)" | Get-ScheduledTaskInfo

# Exécuter manuellement
Start-ScheduledTask -TaskName "win-acme renew (acme-v02.api.letsencrypt.org)"
```

### Créer la tâche manuellement

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Tools\win-acme\wacs.exe" -Argument "--renew --baseuri https://acme-v02.api.letsencrypt.org/"
$trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "win-acme renew" -Action $action -Trigger $trigger -Settings $settings -Principal $principal
```

---

## 9. Certificat wildcard

Les wildcards nécessitent une validation DNS.

### Avec validation DNS manuelle

```powershell
.\wacs.exe --target manual --host "*.example.com,example.com" --validation manual --emailaddress admin@example.com --accepttos
```

### Avec Cloudflare

```powershell
# Installer le plugin Cloudflare (télécharger séparément)
.\wacs.exe --target manual --host "*.example.com,example.com" --validation dns-01 --dnsvalidator cloudflare --cloudflareapitoken YOUR_TOKEN --emailaddress admin@example.com --accepttos
```

---

## 10. Configuration SSL IIS avancée

### Désactiver les protocoles obsolètes

```powershell
# Désactiver SSL 2.0, 3.0, TLS 1.0, 1.1
$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($protocol in $protocols) {
    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"

    New-Item -Path $serverPath -Force | Out-Null
    New-ItemProperty -Path $serverPath -Name "Enabled" -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 1 -PropertyType DWORD -Force | Out-Null

    New-Item -Path $clientPath -Force | Out-Null
    New-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 1 -PropertyType DWORD -Force | Out-Null
}

# Activer TLS 1.2 et 1.3
$modernProtocols = @("TLS 1.2", "TLS 1.3")
foreach ($protocol in $modernProtocols) {
    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"

    New-Item -Path $serverPath -Force | Out-Null
    New-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 0 -PropertyType DWORD -Force | Out-Null

    New-Item -Path $clientPath -Force | Out-Null
    New-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 0 -PropertyType DWORD -Force | Out-Null
}
```

### Redirection HTTP → HTTPS

```powershell
# Installer URL Rewrite Module si nécessaire
# https://www.iis.net/downloads/microsoft/url-rewrite

# Créer la règle via web.config
$webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="HTTP to HTTPS redirect" stopProcessing="true">
                    <match url="(.*)" />
                    <conditions>
                        <add input="{HTTPS}" pattern="off" ignoreCase="true" />
                    </conditions>
                    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
"@

$webConfig | Out-File "C:\inetpub\wwwroot\web.config" -Encoding UTF8
```

---

## 11. HSTS

```powershell
# Ajouter HSTS via IIS
Import-Module WebAdministration

$siteName = "Default Web Site"
$filter = "system.webServer/httpProtocol/customHeaders"

# Ajouter le header HSTS
Add-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter $filter -Name "." -Value @{name="Strict-Transport-Security"; value="max-age=31536000; includeSubDomains"}
```

---

## 12. Gestion des certificats

```powershell
cd C:\Tools\win-acme

# Lister les certificats gérés
.\wacs.exe --list

# Annuler un renouvellement
.\wacs.exe --cancel

# Révoquer un certificat
.\wacs.exe --revoke

# Supprimer toute la configuration
.\wacs.exe --cancel --target all
```

---

## Vérification

```powershell
# Tester le binding HTTPS
Test-NetConnection -ComputerName example.com -Port 443

# Voir le certificat
$cert = (Get-ChildItem Cert:\LocalMachine\WebHosting | Where-Object { $_.Subject -like "*example.com*" })[0]
$cert | Format-List Subject, Issuer, NotBefore, NotAfter, Thumbprint

# Test en ligne
# https://www.ssllabs.com/ssltest/
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Challenge failed | Vérifier DNS, port 80 ouvert |
| Binding non créé | Vérifier hostname dans IIS |
| Certificat non renouvelé | Vérifier la tâche planifiée |
| Rate limit | Utiliser `--test` pour staging |

```powershell
# Logs
Get-Content "C:\ProgramData\win-acme\acme-v02.api.letsencrypt.org\Log\log-*.txt" -Tail 100

# Événements IIS
Get-WinEvent -LogName "Microsoft-IIS-Configuration/Operational" -MaxEvents 20

# Tester manuellement
.\wacs.exe --verbose --renew
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
