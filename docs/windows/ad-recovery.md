---
tags:
  - windows
  - active-directory
  - recovery
  - disaster-recovery
  - backup
---

# Active Directory Recovery

Procédures de récupération Active Directory : restauration d'objets, DSRM, forest recovery.

## Niveaux de Récupération

```
SCÉNARIOS DE RÉCUPÉRATION AD
══════════════════════════════════════════════════════════

Niveau 1 - Objet Supprimé:
└── AD Recycle Bin (si activé)
    └── Restauration simple en quelques secondes

Niveau 2 - Objet Corrompu/Modifié:
└── Authoritative Restore (DSRM)
    └── Restauration d'un DC puis réplication forcée

Niveau 3 - DC Défaillant:
└── Rebuild ou Restore
    └── Cloner depuis un DC existant
    └── Ou restaurer depuis backup

Niveau 4 - Forest Recovery:
└── Disaster Recovery complet
    └── Procédure complexe, tous DCs affectés
    └── Plan de reprise documenté obligatoire
```

---

## AD Recycle Bin

### Activer la Corbeille AD

```powershell
# Prérequis : Forest functional level Windows Server 2008 R2+

# Vérifier le niveau fonctionnel
(Get-ADForest).ForestMode

# Activer la corbeille AD (irréversible)
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
    -Scope ForestOrConfigurationSet `
    -Target (Get-ADForest).Name `
    -Confirm:$false

# Vérifier l'activation
Get-ADOptionalFeature -Filter 'Name -like "Recycle*"'
```

### Restaurer un Objet

```powershell
# Lister les objets supprimés
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties *

# Rechercher un utilisateur supprimé
Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*jdoe*"' `
    -IncludeDeletedObjects -Properties LastKnownParent,whenChanged

# Restaurer un utilisateur
Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*jdoe*"' `
    -IncludeDeletedObjects |
    Restore-ADObject

# Restaurer vers un emplacement spécifique
$user = Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*jdoe*"' -IncludeDeletedObjects
Restore-ADObject -Identity $user -NewName "jdoe" -TargetPath "OU=Users,DC=corp,DC=local"

# Restaurer une OU et son contenu
Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*Finance*" -and ObjectClass -eq "organizationalUnit"' `
    -IncludeDeletedObjects |
    Restore-ADObject -NewName "Finance"

# Restaurer les objets enfants
$ou = "OU=Finance,DC=corp,DC=local"
Get-ADObject -Filter 'isDeleted -eq $true -and LastKnownParent -like "*Finance*"' `
    -IncludeDeletedObjects |
    Restore-ADObject
```

### Durée de Rétention

```powershell
# Voir la durée de rétention (défaut : 180 jours)
(Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -Properties msDS-DeletedObjectLifetime).'msDS-DeletedObjectLifetime'

# Modifier la durée (en jours)
Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -Replace @{'msDS-DeletedObjectLifetime' = 365}
```

---

## Protection des Objets

### Protection contre la Suppression

```powershell
# Activer la protection sur une OU
Set-ADOrganizationalUnit -Identity "OU=Critical,DC=corp,DC=local" `
    -ProtectedFromAccidentalDeletion $true

# Sur un utilisateur
Set-ADUser -Identity jdoe -ProtectedFromAccidentalDeletion $true

# Sur un groupe
Set-ADGroup -Identity "Domain Admins" -ProtectedFromAccidentalDeletion $true

# Vérifier la protection
Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion |
    Select-Object Name, ProtectedFromAccidentalDeletion

# Activer en masse sur toutes les OUs
Get-ADOrganizationalUnit -Filter * |
    Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true
```

---

## Directory Services Restore Mode (DSRM)

### Configuration DSRM

```powershell
# Le mot de passe DSRM est défini lors de la promotion du DC
# Pour le changer :

# Sur le DC concerné
ntdsutil
> set dsrm password
> reset password on server null
> (entrer le nouveau mot de passe)
> quit
> quit

# Ou via PowerShell (Windows Server 2012+)
$password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
Set-ADAccountPassword -Identity "Administrator" -Reset -NewPassword $password `
    -Server "localhost" -AuthType Negotiate

# Synchroniser le mot de passe DSRM avec un compte AD
# (permet d'utiliser un compte AD pour DSRM)
ntdsutil
> set dsrm password
> sync from domain account adminDSRM
> quit
> quit
```

### Démarrer en Mode DSRM

```
Méthode 1 - Au boot:
1. Redémarrer le serveur
2. Appuyer sur F8 pendant le démarrage
3. Sélectionner "Directory Services Restore Mode"

Méthode 2 - Configurer le boot:
bcdedit /set safeboot dsrepair
shutdown /r /t 0

Pour revenir en mode normal:
bcdedit /deletevalue safeboot
shutdown /r /t 0
```

---

## Authoritative Restore

### Procédure Complète

```powershell
# 1. Démarrer le DC en mode DSRM

# 2. Se connecter avec .\Administrator et le mot de passe DSRM

# 3. Restaurer le System State depuis la sauvegarde
wbadmin get versions -backupTarget:E:
wbadmin start systemstaterecovery -version:MM/DD/YYYY-HH:MM -backupTarget:E:

# 4. NE PAS REDÉMARRER - Marquer comme autoritatif

# 5. Lancer ntdsutil
ntdsutil
> activate instance ntds
> authoritative restore

# Restaurer une OU complète
> restore subtree "OU=Finance,DC=corp,DC=local"

# Restaurer un objet unique
> restore object "CN=John Doe,OU=Users,DC=corp,DC=local"

# Quitter
> quit
> quit

# 6. Redémarrer normalement
bcdedit /deletevalue safeboot
shutdown /r /t 0
```

### Augmentation de Version

```
AUTHORITATIVE RESTORE - VERSIONING
══════════════════════════════════════════════════════════

Quand vous faites un restore autoritatif:
1. Le DC restauré a une version ancienne de l'objet
2. Les autres DCs ont la version "supprimée" plus récente
3. Normalement, la version récente gagne (objet reste supprimé)

Solution - Authoritative Restore:
1. Incrémente artificiellement le numéro de version (+100000)
2. Le DC restauré a maintenant la version la plus élevée
3. Les autres DCs répliquent depuis le DC restauré
4. L'objet est "ressuscité" sur tous les DCs
```

---

## Non-Authoritative Restore

```powershell
# Utilisé pour restaurer un DC sans affecter les autres DCs
# Le DC restauré répliquera les données actuelles des autres DCs

# 1. Démarrer en mode DSRM

# 2. Restaurer le System State
wbadmin start systemstaterecovery -version:MM/DD/YYYY-HH:MM -backupTarget:E:

# 3. Redémarrer normalement (sans ntdsutil authoritative restore)
bcdedit /deletevalue safeboot
shutdown /r /t 0

# Le DC synchronisera automatiquement avec les autres DCs
```

---

## Forest Recovery

### Scénario de Disaster Recovery

```
FOREST RECOVERY PROCEDURE
══════════════════════════════════════════════════════════

Scénario: Corruption/compromission affectant toute la forêt

Étapes:
1. Isoler la forêt (couper la réplication avec l'extérieur)
2. Identifier le DC avec la sauvegarde la plus récente valide
3. Restaurer ce DC en mode DSRM
4. Effectuer les nettoyages nécessaires
5. Seize les rôles FSMO
6. Reconstruire les autres DCs (ou les restaurer)
7. Tester et valider
8. Remettre en production
```

### Procédure Détaillée

```powershell
# 1. Isoler le réseau
# → Déconnecter tous les DCs du réseau

# 2. Restaurer le premier DC
# Démarrer en DSRM
# Restaurer le System State

# 3. Nettoyer les métadonnées des autres DCs
ntdsutil
> metadata cleanup
> connections
> connect to server localhost
> quit
> select operation target
> list domains
> select domain 0
> list sites
> select site 0
> list servers in site
# Pour chaque DC corrompu:
> select server X
> quit
> remove selected server

# 4. Saisir les rôles FSMO
Move-ADDirectoryServerOperationMasterRole -Identity "DC01" `
    -OperationMasterRole SchemaMaster,DomainNamingMaster,PDCEmulator,RIDMaster,InfrastructureMaster `
    -Force

# 5. Réinitialiser le compte krbtgt (2 fois, à 10h d'intervalle)
$newPassword = ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword $newPassword

# 6. Reconstruire les autres DCs
# Sur chaque nouveau DC:
Install-ADDSDomainController -DomainName "corp.local" `
    -Credential (Get-Credential) `
    -InstallDns:$true `
    -SiteName "Default-First-Site-Name"
```

### Nettoyage Post-Recovery

```powershell
# Vérifier la réplication
repadmin /replsummary
repadmin /showrepl

# Vérifier les rôles FSMO
netdom query fsmo

# Vérifier la santé DNS
dcdiag /test:dns

# Tester l'authentification
runas /user:corp\testuser cmd

# Vérifier les GPO
Get-GPO -All | ForEach-Object {
    $gpo = $_
    try {
        [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        [PSCustomObject]@{Name = $gpo.DisplayName; Status = "OK"}
    }
    catch {
        [PSCustomObject]@{Name = $gpo.DisplayName; Status = "ERROR"}
    }
}
```

---

## Sauvegarde AD

### Windows Server Backup

```powershell
# Installer la fonctionnalité
Install-WindowsFeature Windows-Server-Backup -IncludeManagementTools

# Sauvegarde System State (inclut AD)
wbadmin start systemstatebackup -backupTarget:E:

# Sauvegarde programmée
$policy = New-WBPolicy
$systemState = New-WBSystemState
Add-WBSystemState -Policy $policy
$target = New-WBBackupTarget -VolumePath "E:"
Add-WBBackupTarget -Policy $policy -Target $target
Set-WBSchedule -Policy $policy -Schedule 02:00
Set-WBPolicy -Policy $policy

# Lister les sauvegardes
wbadmin get versions
```

### Bonnes Pratiques de Sauvegarde

```powershell
# Script de sauvegarde AD avec vérification
$backupTarget = "E:"
$logFile = "C:\Logs\AD-Backup-$(Get-Date -Format 'yyyyMMdd').log"

# Vérifier la santé avant backup
$dcdiag = dcdiag /q
if ($LASTEXITCODE -ne 0) {
    "$(Get-Date) - WARNING: DCDiag reported issues" | Out-File $logFile -Append
}

# Effectuer la sauvegarde
$result = wbadmin start systemstatebackup -backupTarget:$backupTarget -quiet
"$(Get-Date) - Backup result: $result" | Out-File $logFile -Append

# Vérifier la sauvegarde
$versions = wbadmin get versions -backupTarget:$backupTarget
"$(Get-Date) - Available versions: $versions" | Out-File $logFile -Append

# Nettoyer les anciennes sauvegardes (garder 7 jours)
# Note: Windows Server Backup gère automatiquement la rétention
```

---

## Tombstone et Objets Lingering

### Tombstone Lifetime

```powershell
# Voir le tombstone lifetime (défaut : 180 jours)
(Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -Properties tombstoneLifetime).tombstoneLifetime

# Modifier (avec précaution)
Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -Replace @{tombstoneLifetime = 365}

# ⚠️ Ne jamais restaurer une sauvegarde plus ancienne que le tombstone lifetime
```

### Objets Lingering

```powershell
# Les objets "lingering" apparaissent quand un DC est resté hors ligne
# plus longtemps que le tombstone lifetime

# Détecter les objets lingering
repadmin /removelingeringobjects DC01.corp.local DC02.corp.local "DC=corp,DC=local" /advisory_mode

# Supprimer les objets lingering
repadmin /removelingeringobjects DC01.corp.local DC02.corp.local "DC=corp,DC=local"

# Activer le strict replication consistency (recommandé)
repadmin /regkey DC01 +strict
```

---

## Tests et Validation

### Procédure de Test

```powershell
# Script de validation post-restore
function Test-ADRecovery {
    $results = @()

    # Test 1: Services AD
    $services = @("NTDS", "DNS", "Netlogon", "DFSR")
    foreach ($svc in $services) {
        $status = Get-Service $svc -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            Test = "Service $svc"
            Result = if ($status.Status -eq "Running") { "PASS" } else { "FAIL" }
        }
    }

    # Test 2: FSMO Roles
    $fsmo = netdom query fsmo 2>&1
    $results += [PSCustomObject]@{
        Test = "FSMO Roles"
        Result = if ($LASTEXITCODE -eq 0) { "PASS" } else { "FAIL" }
    }

    # Test 3: Réplication
    $repl = repadmin /replsummary 2>&1
    $results += [PSCustomObject]@{
        Test = "Replication"
        Result = if ($repl -notmatch "fail") { "PASS" } else { "WARN" }
    }

    # Test 4: DCDiag
    $dcdiag = dcdiag /q 2>&1
    $results += [PSCustomObject]@{
        Test = "DCDiag"
        Result = if ($LASTEXITCODE -eq 0) { "PASS" } else { "WARN" }
    }

    # Test 5: DNS
    $dns = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.corp.local" -Type SRV -ErrorAction SilentlyContinue
    $results += [PSCustomObject]@{
        Test = "DNS SRV Records"
        Result = if ($dns) { "PASS" } else { "FAIL" }
    }

    return $results
}

Test-ADRecovery | Format-Table -AutoSize
```

---

## Bonnes Pratiques

```yaml
Checklist AD Recovery:
  Prévention:
    - [ ] AD Recycle Bin activé
    - [ ] Protection des OUs critiques
    - [ ] Sauvegardes System State quotidiennes
    - [ ] Test de restauration mensuel

  Documentation:
    - [ ] Procédure de recovery documentée
    - [ ] Mots de passe DSRM sécurisés et accessibles
    - [ ] Contacts d'escalade identifiés
    - [ ] Schéma de l'infrastructure AD à jour

  Sauvegardes:
    - [ ] Minimum 2 DCs sauvegardés
    - [ ] Rétention > 14 jours (idéalement 30+)
    - [ ] Sauvegarde hors-site/cloud
    - [ ] Test de restauration régulier

  Monitoring:
    - [ ] Alertes sur échecs de réplication
    - [ ] Surveillance des sauvegardes
    - [ ] Audit des suppressions d'objets
```

---

**Voir aussi :**

- [Active Directory](active-directory.md) - Fondamentaux AD
- [AD Sites & Replication](ad-sites-replication.md) - Réplication
- [Event Logs](event-logs.md) - Journaux d'événements
