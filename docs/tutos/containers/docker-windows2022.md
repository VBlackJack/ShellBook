---
tags:
  - tutos
  - containers
  - docker
  - windows
---

# Docker sur Windows Server 2022

Installation de **Docker** sur Windows Server 2022 pour conteneurs Windows et Linux.

| Composant | Version |
|-----------|---------|
| Windows Server | 2022 |
| Docker | 24.x |
| Containers Feature | Intégré |

**Durée estimée :** 30 minutes

---

## Types de conteneurs

| Type | Base Image | Isolation | Usage |
|------|------------|-----------|-------|
| Windows | windows/servercore | Process/Hyper-V | Apps .NET, IIS |
| Linux | Alpine, Debian... | WSL2/Hyper-V | Apps Linux |

---

## 1. Prérequis

### Activer la fonctionnalité Containers

```powershell
# Vérifier Windows Server 2022
Get-ComputerInfo | Select-Object WindowsProductName, OsVersion

# Installer la fonctionnalité Containers
Install-WindowsFeature -Name Containers -Restart
```

### Activer Hyper-V (optionnel, pour isolation)

```powershell
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
```

---

## 2. Installation de Docker

### Via PowerShell (recommandé)

```powershell
# Installer le module DockerMsftProvider
Install-Module -Name DockerMsftProvider -Repository PSGallery -Force

# Installer Docker
Install-Package -Name docker -ProviderName DockerMsftProvider -Force

# Redémarrer
Restart-Computer
```

### Après redémarrage

```powershell
# Démarrer Docker
Start-Service Docker

# Configurer démarrage automatique
Set-Service -Name Docker -StartupType Automatic

# Vérifier
docker version
docker info
```

---

## 3. Configuration

### Fichier daemon.json

```powershell
# Créer le répertoire config
New-Item -ItemType Directory -Path C:\ProgramData\docker\config -Force

# Configuration
@"
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-opts": [
    "size=120GB"
  ]
}
"@ | Set-Content C:\ProgramData\docker\config\daemon.json

Restart-Service Docker
```

---

## 4. Conteneurs Windows

### Images de base

```powershell
# Server Core (complet)
docker pull mcr.microsoft.com/windows/servercore:ltsc2022

# Nano Server (minimal)
docker pull mcr.microsoft.com/windows/nanoserver:ltsc2022

# IIS
docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

# .NET Framework
docker pull mcr.microsoft.com/dotnet/framework/aspnet:4.8-windowsservercore-ltsc2022

# .NET Core/5+
docker pull mcr.microsoft.com/dotnet/aspnet:8.0-nanoserver-ltsc2022
```

### Lancer un conteneur IIS

```powershell
# IIS simple
docker run -d --name web -p 8080:80 mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

# Avec volume
docker run -d --name web -p 8080:80 `
    -v C:\inetpub\wwwroot:C:\inetpub\wwwroot `
    mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

# Tester
Start-Process "http://localhost:8080"
```

### Isolation Hyper-V

```powershell
# Isolation par processus (par défaut, plus rapide)
docker run -d --isolation=process mcr.microsoft.com/windows/servercore:ltsc2022

# Isolation Hyper-V (plus sécurisée)
docker run -d --isolation=hyperv mcr.microsoft.com/windows/servercore:ltsc2022
```

---

## 5. Conteneurs Linux (LCOW)

### Activer Linux Containers on Windows

```powershell
# Installer WSL2 (Windows Server 2022+)
wsl --install

# Configurer Docker pour Linux
# Dans daemon.json, ajouter:
# "features": { "buildkit": true }

# Ou switcher manuellement
& 'C:\Program Files\Docker\Docker\DockerCli.exe' -SwitchLinuxEngine
```

### Utiliser des conteneurs Linux

```powershell
docker run -d --name nginx -p 80:80 nginx:alpine
docker run -d --name redis redis:alpine
```

---

## 6. Dockerfile Windows

### Application .NET Framework

```dockerfile
FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8-windowsservercore-ltsc2022

WORKDIR /inetpub/wwwroot

COPY ./publish/ .

EXPOSE 80

ENTRYPOINT ["C:\\ServiceMonitor.exe", "w3svc"]
```

### Application .NET 8

```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0-nanoserver-ltsc2022 AS build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0-nanoserver-ltsc2022
WORKDIR /app
COPY --from=build /app .
EXPOSE 80
ENTRYPOINT ["dotnet", "MyApp.dll"]
```

### Build

```powershell
docker build -t myapp:1.0 .
docker run -d -p 8080:80 myapp:1.0
```

---

## 7. Docker Compose

### Installation

```powershell
# Docker Compose est inclus avec Docker Desktop
# Pour Windows Server, télécharger séparément
$version = "2.23.0"
Invoke-WebRequest "https://github.com/docker/compose/releases/download/v$version/docker-compose-windows-x86_64.exe" -OutFile "$env:ProgramFiles\Docker\docker-compose.exe"
```

### Exemple compose.yml

```yaml
version: '3.8'

services:
  web:
    image: mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022
    ports:
      - "80:80"
    volumes:
      - type: bind
        source: C:\inetpub\wwwroot
        target: C:\inetpub\wwwroot
    isolation: process

  api:
    build:
      context: ./api
      dockerfile: Dockerfile
    ports:
      - "5000:80"
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
    depends_on:
      - db

  db:
    image: mcr.microsoft.com/mssql/server:2022-latest
    ports:
      - "1433:1433"
    environment:
      - ACCEPT_EULA=Y
      - SA_PASSWORD=YourStrong!Passw0rd
    volumes:
      - sqldata:C:\var\opt\mssql

volumes:
  sqldata:
```

```powershell
docker-compose up -d
docker-compose logs -f
docker-compose down
```

---

## 8. Réseaux Windows

### Types de réseaux

```powershell
# NAT (par défaut)
docker network create -d nat mynat

# Transparent (accès réseau direct)
docker network create -d transparent mytrans

# L2Bridge
docker network create -d l2bridge mybridge

# Overlay (Swarm)
docker network create -d overlay myoverlay
```

### Utilisation

```powershell
docker run -d --network mynat --name web nginx
docker network inspect mynat
```

---

## 9. Volumes Windows

```powershell
# Créer un volume
docker volume create mydata

# Utiliser
docker run -d -v mydata:C:\data mcr.microsoft.com/windows/servercore:ltsc2022

# Bind mount
docker run -d -v C:\HostPath:C:\ContainerPath:ro myimage

# Lister
docker volume ls
```

---

## 10. Firewall

```powershell
# Docker crée automatiquement les règles
# Pour vérifier
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Docker*" }

# Ajouter manuellement si nécessaire
New-NetFirewallRule -DisplayName "Docker Port 8080" `
    -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
```

---

## 11. Monitoring

```powershell
# Stats temps réel
docker stats

# Événements
docker events

# Espace disque
docker system df

# Logs
docker logs container_name
docker logs -f --tail 100 container_name
```

---

## 12. Nettoyage

```powershell
# Conteneurs arrêtés
docker container prune -f

# Images non utilisées
docker image prune -a -f

# Volumes
docker volume prune -f

# Tout
docker system prune -a --volumes -f
```

---

## 13. Troubleshooting

### Logs Docker

```powershell
# Logs du daemon
Get-EventLog -LogName Application -Source Docker -Newest 50

# Ou
Get-Content C:\ProgramData\docker\daemon.log -Tail 100
```

### Problèmes courants

| Problème | Solution |
|----------|----------|
| Image not found | Vérifier tag :ltsc2022 |
| Network error | `docker network prune` |
| Hyper-V isolation fail | Vérifier Hyper-V installé |
| Container exit | `docker logs container_name` |

```powershell
# Réinitialiser Docker
Stop-Service Docker
Remove-Item -Recurse C:\ProgramData\docker -Force
Start-Service Docker
```

---

## Vérification

```powershell
docker version
docker info
docker run --rm mcr.microsoft.com/windows/nanoserver:ltsc2022 cmd /c echo Hello
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
