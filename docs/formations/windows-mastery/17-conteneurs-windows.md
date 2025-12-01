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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Conteneuriser une application web ASP.NET avec SQL Server en utilisant Docker et Docker Compose, puis déployer sur Azure Container Registry

    **Contexte** : Votre équipe souhaite moderniser une application ASP.NET existante en la conteneurisant pour faciliter le déploiement et la scalabilité. L'application utilise SQL Server comme base de données. Vous devez créer des images Docker optimisées, orchestrer les conteneurs avec Docker Compose, et préparer le déploiement vers Azure.

    **Tâches à réaliser** :

    1. Installer Docker sur Windows Server 2022 et télécharger les images de base `windowsservercore:ltsc2022` et `mssql/server:2019-latest`
    2. Créer une application ASP.NET simple avec une page qui se connecte à SQL Server et affiche une liste d'items depuis la base de données
    3. Écrire un Dockerfile multi-stage qui compile l'application avec l'image SDK, puis crée une image de runtime optimisée basée sur `aspnet:6.0-windowsservercore-ltsc2022`
    4. Créer un fichier `docker-compose.yml` qui orchestre deux services : l'application web (port 8080) et SQL Server (avec volume persistant pour les données)
    5. Implémenter un script d'initialisation SQL qui crée automatiquement la base de données et une table de test lors du premier démarrage
    6. Tagger les images et les pousser vers un Azure Container Registry, puis tester le pull depuis le registry

    **Critères de validation** :

    - [ ] Docker est installé et `docker version` fonctionne correctement
    - [ ] Les images de base sont téléchargées : `docker images` montre windowsservercore et mssql/server
    - [ ] Le Dockerfile compile l'application sans erreurs et crée une image finale de moins de 8 GB
    - [ ] `docker-compose up` démarre les deux conteneurs sans erreurs
    - [ ] L'application est accessible sur `http://localhost:8080` et affiche les données de la base
    - [ ] Les données SQL Server persistent après un `docker-compose down/up` (test du volume)
    - [ ] Les images sont présentes dans Azure Container Registry et peuvent être téléchargées avec `docker pull`

??? quote "Solution"
    **Étape 1 : Installation de Docker sur Windows Server**

    ```powershell
    # Installer la feature Containers
    Install-WindowsFeature -Name Containers

    # Redémarrer (obligatoire)
    Restart-Computer -Force

    # Après le redémarrage, installer Docker
    Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
    Install-Package -Name docker -ProviderName DockerMsftProvider -Force

    # Démarrer le service Docker
    Start-Service Docker

    # Vérifier l'installation
    docker version
    docker info

    # Télécharger les images de base
    docker pull mcr.microsoft.com/windows/servercore:ltsc2022
    docker pull mcr.microsoft.com/dotnet/aspnet:6.0-windowsservercore-ltsc2022
    docker pull mcr.microsoft.com/dotnet/sdk:6.0-windowsservercore-ltsc2022
    docker pull mcr.microsoft.com/mssql/server:2019-latest

    # Vérifier les images
    docker images
    ```

    **Étape 2 : Créer l'application ASP.NET**

    ```powershell
    # Créer la structure du projet
    New-Item -Path "C:\ContainerDemo" -ItemType Directory -Force
    Set-Location "C:\ContainerDemo"

    # Créer un projet ASP.NET Web API
    dotnet new webapi -n ItemsApi -f net6.0

    Set-Location ItemsApi

    # Ajouter le package SQL Server
    dotnet add package Microsoft.Data.SqlClient
    dotnet add package Dapper
    ```

    Modifier `Program.cs` :

    ```csharp
    using Microsoft.Data.SqlClient;
    using Dapper;

    var builder = WebApplication.CreateBuilder(args);

    // Configuration de la connection string depuis les variables d'environnement
    var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection")
        ?? "Server=sqlserver;Database=ItemsDB;User Id=sa;Password=P@ssw0rd123!;TrustServerCertificate=True;";

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    var app = builder.Build();

    app.UseSwagger();
    app.UseSwaggerUI();

    // Endpoint pour vérifier la santé
    app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

    // Endpoint pour lister les items
    app.MapGet("/api/items", async () =>
    {
        try
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            var items = await connection.QueryAsync<Item>(
                "SELECT Id, Name, Description, CreatedAt FROM Items ORDER BY CreatedAt DESC"
            );

            return Results.Ok(new { success = true, count = items.Count(), items });
        }
        catch (Exception ex)
        {
            return Results.Problem(
                detail: ex.Message,
                statusCode: 500,
                title: "Database Error"
            );
        }
    });

    // Endpoint pour créer un item
    app.MapPost("/api/items", async (Item item) =>
    {
        try
        {
            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            var id = await connection.ExecuteScalarAsync<int>(
                "INSERT INTO Items (Name, Description, CreatedAt) VALUES (@Name, @Description, GETDATE()); SELECT CAST(SCOPE_IDENTITY() as int)",
                item
            );

            item.Id = id;
            return Results.Created($"/api/items/{id}", item);
        }
        catch (Exception ex)
        {
            return Results.Problem(
                detail: ex.Message,
                statusCode: 500,
                title: "Database Error"
            );
        }
    });

    // Page HTML simple
    app.MapGet("/", () => Results.Content(@"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Items App - Windows Container Demo</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
            .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h1 { color: #0078d4; }
            .item { padding: 10px; margin: 10px 0; background: #f9f9f9; border-left: 4px solid #0078d4; }
            button { background: #0078d4; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #005a9e; }
            input { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
            .status { padding: 10px; margin: 10px 0; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <h1>Items Management - Windows Container Demo</h1>
            <div class='status' id='status'>Loading...</div>

            <h2>Add New Item</h2>
            <input type='text' id='name' placeholder='Item name' />
            <input type='text' id='description' placeholder='Description' />
            <button onclick='addItem()'>Add Item</button>

            <h2>Items List</h2>
            <div id='items'></div>
        </div>

        <script>
        async function loadItems() {
            try {
                const response = await fetch('/api/items');
                const data = await response.json();

                document.getElementById('status').innerHTML =
                    `✓ Connected to SQL Server | ${data.count} items in database`;

                const itemsHtml = data.items.map(item => `
                    <div class='item'>
                        <strong>${item.name}</strong> - ${item.description}
                        <br><small>Created: ${new Date(item.createdAt).toLocaleString()}</small>
                    </div>
                `).join('');

                document.getElementById('items').innerHTML = itemsHtml || '<p>No items yet</p>';
            } catch (error) {
                document.getElementById('status').innerHTML = '✗ Error: ' + error.message;
                document.getElementById('status').style.background = '#f8d7da';
            }
        }

        async function addItem() {
            const name = document.getElementById('name').value;
            const description = document.getElementById('description').value;

            if (!name) {
                alert('Please enter a name');
                return;
            }

            try {
                await fetch('/api/items', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, description })
                });

                document.getElementById('name').value = '';
                document.getElementById('description').value = '';
                loadItems();
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        loadItems();
        setInterval(loadItems, 5000);
        </script>
    </body>
    </html>
    ", "text/html"));

    app.Run();

    public record Item
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }
    ```

    **Étape 3 : Créer le Dockerfile multi-stage**

    Créer `C:\ContainerDemo\ItemsApi\Dockerfile` :

    ```dockerfile
    # Stage 1: Build
    FROM mcr.microsoft.com/dotnet/sdk:6.0-windowsservercore-ltsc2022 AS build
    WORKDIR /src

    # Copier le fichier projet et restaurer les dépendances
    COPY ["ItemsApi.csproj", "./"]
    RUN dotnet restore "ItemsApi.csproj"

    # Copier tout le code source et compiler
    COPY . .
    RUN dotnet build "ItemsApi.csproj" -c Release -o /app/build
    RUN dotnet publish "ItemsApi.csproj" -c Release -o /app/publish

    # Stage 2: Runtime
    FROM mcr.microsoft.com/dotnet/aspnet:6.0-windowsservercore-ltsc2022 AS runtime
    WORKDIR /app

    # Copier les fichiers publiés depuis le stage de build
    COPY --from=build /app/publish .

    # Exposer le port
    EXPOSE 80

    # Point d'entrée
    ENTRYPOINT ["dotnet", "ItemsApi.dll"]
    ```

    Créer `.dockerignore` :

    ```
    bin/
    obj/
    .vs/
    *.user
    ```

    **Étape 4 : Créer le docker-compose.yml**

    Créer `C:\ContainerDemo\docker-compose.yml` :

    ```yaml
    version: '3.8'

    services:
      sqlserver:
        image: mcr.microsoft.com/mssql/server:2019-latest
        container_name: sqlserver
        environment:
          - ACCEPT_EULA=Y
          - SA_PASSWORD=P@ssw0rd123!
          - MSSQL_PID=Developer
        ports:
          - "1433:1433"
        volumes:
          - sqldata:/var/opt/mssql
          - ./init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
        healthcheck:
          test: ["CMD-SHELL", "sqlcmd -S localhost -U sa -P P@ssw0rd123! -Q 'SELECT 1' || exit 1"]
          interval: 10s
          timeout: 5s
          retries: 5
        networks:
          - app-network

      webapp:
        build:
          context: ./ItemsApi
          dockerfile: Dockerfile
        container_name: webapp
        environment:
          - ASPNETCORE_URLS=http://+:80
          - ConnectionStrings__DefaultConnection=Server=sqlserver;Database=ItemsDB;User Id=sa;Password=P@ssw0rd123!;TrustServerCertificate=True;
        ports:
          - "8080:80"
        depends_on:
          sqlserver:
            condition: service_healthy
        networks:
          - app-network
        restart: unless-stopped

    volumes:
      sqldata:
        driver: local

    networks:
      app-network:
        driver: nat
    ```

    **Étape 5 : Script d'initialisation SQL**

    Créer `C:\ContainerDemo\init-db.sql` :

    ```sql
    -- init-db.sql
    USE master;
    GO

    IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'ItemsDB')
    BEGIN
        CREATE DATABASE ItemsDB;
    END
    GO

    USE ItemsDB;
    GO

    IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Items')
    BEGIN
        CREATE TABLE Items (
            Id INT IDENTITY(1,1) PRIMARY KEY,
            Name NVARCHAR(200) NOT NULL,
            Description NVARCHAR(MAX),
            CreatedAt DATETIME2 NOT NULL DEFAULT GETDATE()
        );

        -- Insérer des données de test
        INSERT INTO Items (Name, Description) VALUES
        ('Windows Server 2022', 'Dernière version de Windows Server avec support des conteneurs'),
        ('Docker Desktop', 'Plateforme de conteneurisation pour Windows'),
        ('Azure Container Registry', 'Registry privé pour vos images Docker'),
        ('Kubernetes', 'Orchestration de conteneurs à grande échelle');
    END
    GO
    ```

    Pour que SQL Server exécute ce script au démarrage, créez un script PowerShell :

    Créer `C:\ContainerDemo\entrypoint.ps1` :

    ```powershell
    # Attendre que SQL Server soit prêt
    $maxRetries = 30
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        try {
            sqlcmd -S localhost -U sa -P $env:SA_PASSWORD -Q "SELECT 1" -b
            Write-Host "SQL Server is ready!"
            break
        }
        catch {
            $retryCount++
            Write-Host "Waiting for SQL Server... ($retryCount/$maxRetries)"
            Start-Sleep -Seconds 2
        }
    }

    # Exécuter le script d'initialisation
    sqlcmd -S localhost -U sa -P $env:SA_PASSWORD -i /docker-entrypoint-initdb.d/init-db.sql
    ```

    **Build et démarrage**

    ```powershell
    # Se placer dans le répertoire
    Set-Location "C:\ContainerDemo"

    # Build l'image de l'application
    docker build -t itemsapi:1.0 ./ItemsApi

    # Vérifier l'image
    docker images itemsapi

    # Démarrer avec Docker Compose
    docker-compose up -d

    # Surveiller les logs
    docker-compose logs -f

    # Vérifier l'état des conteneurs
    docker-compose ps

    # Tester l'application
    Start-Process "http://localhost:8080"

    # Test API
    Invoke-RestMethod -Uri "http://localhost:8080/health"
    Invoke-RestMethod -Uri "http://localhost:8080/api/items"

    # Initialiser la base manuellement si nécessaire
    docker exec sqlserver /opt/mssql-tools/bin/sqlcmd `
        -S localhost -U sa -P "P@ssw0rd123!" `
        -Q "USE master; IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'ItemsDB') CREATE DATABASE ItemsDB;"

    docker exec sqlserver /opt/mssql-tools/bin/sqlcmd `
        -S localhost -U sa -P "P@ssw0rd123!" `
        -i /docker-entrypoint-initdb.d/init-db.sql
    ```

    **Étape 6 : Azure Container Registry**

    ```powershell
    # Installer Azure CLI si nécessaire
    # winget install Microsoft.AzureCLI

    # Se connecter à Azure
    az login

    # Créer un Resource Group
    az group create --name rg-containers --location westeurope

    # Créer un Azure Container Registry
    az acr create --resource-group rg-containers `
        --name mycontainersacr001 `
        --sku Basic

    # Se connecter au registry
    az acr login --name mycontainersacr001

    # Obtenir le login server
    $acrLoginServer = az acr show --name mycontainersacr001 `
        --query loginServer --output tsv

    Write-Host "ACR Login Server: $acrLoginServer"

    # Tagger l'image pour ACR
    docker tag itemsapi:1.0 "$acrLoginServer/itemsapi:1.0"
    docker tag itemsapi:1.0 "$acrLoginServer/itemsapi:latest"

    # Pousser vers ACR
    docker push "$acrLoginServer/itemsapi:1.0"
    docker push "$acrLoginServer/itemsapi:latest"

    # Lister les images dans ACR
    az acr repository list --name mycontainersacr001 --output table

    # Voir les tags
    az acr repository show-tags --name mycontainersacr001 `
        --repository itemsapi --output table

    # Tester le pull depuis ACR
    docker rmi "$acrLoginServer/itemsapi:1.0"
    docker pull "$acrLoginServer/itemsapi:1.0"

    # Créer un service principal pour l'accès programmatique
    $acrId = az acr show --name mycontainersacr001 --query id --output tsv

    $spCredentials = az ad sp create-for-rbac `
        --name "acr-service-principal" `
        --role acrpull `
        --scopes $acrId

    # Les credentials sont affichés, les sauvegarder pour usage ultérieur
    ```

    **Test de persistance des données**

    ```powershell
    # Arrêter les conteneurs
    docker-compose down

    # Redémarrer
    docker-compose up -d

    # Attendre que les services démarrent
    Start-Sleep -Seconds 20

    # Vérifier que les données sont toujours là
    $items = Invoke-RestMethod -Uri "http://localhost:8080/api/items"
    Write-Host "Nombre d'items après redémarrage : $($items.count)"

    if ($items.count -gt 0) {
        Write-Host "✓ Les données ont persisté!" -ForegroundColor Green
    } else {
        Write-Host "✗ Les données ont été perdues" -ForegroundColor Red
    }
    ```

    **Nettoyage**

    ```powershell
    # Arrêter et supprimer les conteneurs
    docker-compose down

    # Supprimer les volumes (ATTENTION : supprime les données)
    docker-compose down -v

    # Nettoyer les images
    docker rmi itemsapi:1.0
    docker rmi "$acrLoginServer/itemsapi:1.0"
    docker rmi "$acrLoginServer/itemsapi:latest"

    # Supprimer le registry Azure (optionnel)
    az acr delete --name mycontainersacr001 --resource-group rg-containers --yes
    az group delete --name rg-containers --yes
    ```

    **Monitoring et troubleshooting**

    ```powershell
    # Voir les logs en temps réel
    docker-compose logs -f webapp
    docker-compose logs -f sqlserver

    # Inspecter un conteneur
    docker inspect webapp

    # Exécuter des commandes dans le conteneur
    docker exec -it webapp powershell

    # Vérifier la connectivité réseau
    docker network ls
    docker network inspect containerapp_app-network

    # Statistiques de ressources
    docker stats

    # Événements Docker
    docker events --since '10m'
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
