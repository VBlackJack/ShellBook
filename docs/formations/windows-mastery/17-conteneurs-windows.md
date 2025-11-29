---
tags:
  - formation
  - windows-server
  - conteneurs
  - docker
  - kubernetes
---

# Module 17 : Conteneurs Windows

## Objectifs du Module

Ce module couvre la conteneurisation sur Windows Server :

- Comprendre les conteneurs Windows vs Linux
- Installer et configurer Docker sur Windows
- Créer des images Windows Container
- Déployer sur Azure Kubernetes Service (AKS)
- Utiliser Windows Containers en production

**Durée :** 9 heures

**Niveau :** Expert

---

## 1. Introduction aux Conteneurs Windows

### 1.1 Types de Conteneurs Windows

```
TYPES DE CONTENEURS WINDOWS
───────────────────────────

Windows Server Containers
├── Isolation au niveau processus
├── Kernel partagé avec l'hôte
├── Performance maximale
└── Usage: Dev, CI/CD, workloads légers

Hyper-V Containers
├── Isolation complète (VM légère)
├── Kernel séparé par conteneur
├── Sécurité maximale
└── Usage: Multi-tenant, workloads non fiables

Images de Base
├── Windows Server Core (~2.5 GB)
├── Nano Server (~100 MB)
├── Windows (~6 GB, avec GUI)
└── Windows Server IoT (~800 MB)
```

### 1.2 Compatibilité des Versions

```
MATRICE DE COMPATIBILITÉ
────────────────────────

Hôte                    Images supportées
────                    ─────────────────
Windows Server 2022     - Windows Server 2022
                        - Windows Server 2019 (process isolation)
                        - Hyper-V: toutes versions

Windows Server 2019     - Windows Server 2019
                        - Windows Server 2016 (Hyper-V only)

RÈGLE: Version conteneur <= Version hôte (sauf Hyper-V)
```

---

## 2. Installation Docker

### 2.1 Docker sur Windows Server

```powershell
# Installer la feature Containers
Install-WindowsFeature -Name Containers

# Installer Docker
Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
Install-Package -Name docker -ProviderName DockerMsftProvider -Force

# Redémarrer
Restart-Computer

# Vérifier
docker version
docker info
```

### 2.2 Docker Desktop (Développement)

```powershell
# Sur Windows 10/11 avec WSL2 ou Hyper-V
# Télécharger Docker Desktop depuis docker.com

# Activer les conteneurs Windows
# Docker Desktop → Settings → General → Use Windows containers

# Ou via ligne de commande
& 'C:\Program Files\Docker\Docker\DockerCli.exe' -SwitchDaemon
```

---

## 3. Images et Conteneurs

### 3.1 Gestion des Images

```powershell
# Télécharger une image de base
docker pull mcr.microsoft.com/windows/servercore:ltsc2022
docker pull mcr.microsoft.com/windows/nanoserver:ltsc2022

# Lister les images
docker images

# Supprimer une image
docker rmi <image_id>

# Nettoyer les images inutilisées
docker image prune -a
```

### 3.2 Exécuter des Conteneurs

```powershell
# Conteneur interactif
docker run -it mcr.microsoft.com/windows/servercore:ltsc2022 powershell

# Conteneur en arrière-plan
docker run -d --name web -p 80:80 mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

# Hyper-V isolation
docker run --isolation=hyperv -it mcr.microsoft.com/windows/servercore:ltsc2022 powershell

# Lister les conteneurs
docker ps
docker ps -a

# Logs
docker logs web

# Exécuter une commande dans un conteneur
docker exec -it web powershell

# Arrêter/Supprimer
docker stop web
docker rm web
```

---

## 4. Création d'Images

### 4.1 Dockerfile

```dockerfile
# Dockerfile pour une application ASP.NET
FROM mcr.microsoft.com/dotnet/aspnet:6.0-windowsservercore-ltsc2022

WORKDIR /app
COPY ./publish .

EXPOSE 80
ENTRYPOINT ["dotnet", "MyApp.dll"]
```

```dockerfile
# Dockerfile pour IIS avec application
FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

# Installer des features IIS
RUN powershell -Command \
    Install-WindowsFeature Web-Asp-Net45; \
    Remove-Item -Recurse C:\inetpub\wwwroot\*

# Copier l'application
COPY ./webapp /inetpub/wwwroot

EXPOSE 80
```

### 4.2 Build et Push

```powershell
# Build
docker build -t myapp:1.0 .

# Tag pour registry
docker tag myapp:1.0 myregistry.azurecr.io/myapp:1.0

# Login au registry
docker login myregistry.azurecr.io

# Push
docker push myregistry.azurecr.io/myapp:1.0
```

---

## 5. Docker Compose

### 5.1 Exemple Multi-Conteneurs

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    image: mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022
    ports:
      - "80:80"
    volumes:
      - ./website:/inetpub/wwwroot
    depends_on:
      - db

  db:
    image: mcr.microsoft.com/mssql/server:2019-latest
    environment:
      - ACCEPT_EULA=Y
      - SA_PASSWORD=P@ssw0rd123!
    ports:
      - "1433:1433"
    volumes:
      - sqldata:/var/opt/mssql

volumes:
  sqldata:
```

```powershell
# Démarrer
docker-compose up -d

# Arrêter
docker-compose down

# Voir les logs
docker-compose logs -f
```

---

## 6. Kubernetes et AKS

### 6.1 Déploiement sur AKS

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: windows-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: windows-app
  template:
    metadata:
      labels:
        app: windows-app
    spec:
      nodeSelector:
        kubernetes.io/os: windows
      containers:
      - name: windows-app
        image: myregistry.azurecr.io/myapp:1.0
        ports:
        - containerPort: 80
        resources:
          limits:
            cpu: "1"
            memory: "2Gi"
---
apiVersion: v1
kind: Service
metadata:
  name: windows-app-svc
spec:
  type: LoadBalancer
  ports:
  - port: 80
  selector:
    app: windows-app
```

```powershell
# Déployer sur AKS
kubectl apply -f deployment.yaml

# Vérifier
kubectl get pods -o wide
kubectl get svc
```

---

## 7. Exercice Pratique

### Conteneuriser une Application IIS

```powershell
# 1. Créer la structure
mkdir C:\ContainerDemo
cd C:\ContainerDemo

# 2. Créer une page web simple
@"
<!DOCTYPE html>
<html>
<head><title>Container Demo</title></head>
<body>
<h1>Hello from Windows Container!</h1>
<p>Server: <%= Request.ServerVariables("SERVER_NAME") %></p>
</body>
</html>
"@ | Set-Content "index.asp"

# 3. Créer le Dockerfile
@"
FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022
RUN powershell -Command Install-WindowsFeature Web-ASP
COPY index.asp /inetpub/wwwroot/
EXPOSE 80
"@ | Set-Content "Dockerfile"

# 4. Build
docker build -t webapp:1.0 .

# 5. Exécuter
docker run -d -p 8080:80 --name webapp webapp:1.0

# 6. Tester
Start-Process "http://localhost:8080"

# 7. Nettoyer
docker stop webapp
docker rm webapp
```

---

## Quiz

1. **Quelle image de base Windows est la plus légère ?**
   - [ ] A. Windows Server Core
   - [ ] B. Nano Server
   - [ ] C. Windows

2. **Quel type d'isolation offre une sécurité maximale ?**
   - [ ] A. Process isolation
   - [ ] B. Hyper-V isolation
   - [ ] C. Network isolation

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 16 : Haute Disponibilité](16-haute-disponibilite.md)

**Suivant :** [Module 18 : Hybrid Cloud](18-hybrid-cloud.md)
