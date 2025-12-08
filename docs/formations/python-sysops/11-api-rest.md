---
tags:
  - formation
  - python
  - api
  - rest
  - http
  - requests
---

# Module 11 - APIs REST & HTTP

Interagir avec des APIs REST pour l'automatisation et l'intégration.

---

## Objectifs du Module

- Comprendre les principes REST
- Maîtriser la bibliothèque requests
- Gérer l'authentification
- Créer des clients API robustes

---

## 1. Principes REST

### Méthodes HTTP

| Méthode | Action | Idempotent |
|---------|--------|------------|
| GET | Lire une ressource | Oui |
| POST | Créer une ressource | Non |
| PUT | Remplacer une ressource | Oui |
| PATCH | Modifier partiellement | Non |
| DELETE | Supprimer une ressource | Oui |

### Codes de Statut

```python
# 2xx - Succès
200  # OK
201  # Created
204  # No Content

# 3xx - Redirection
301  # Moved Permanently
302  # Found (Temporary Redirect)
304  # Not Modified

# 4xx - Erreur Client
400  # Bad Request
401  # Unauthorized
403  # Forbidden
404  # Not Found
429  # Too Many Requests

# 5xx - Erreur Serveur
500  # Internal Server Error
502  # Bad Gateway
503  # Service Unavailable
```

---

## 2. Bibliothèque requests

### Installation

```bash
pip install requests
```

### Requêtes de Base

```python
import requests

# GET
response = requests.get("https://api.example.com/users")
print(response.status_code)    # 200
print(response.json())         # Données JSON
print(response.text)           # Texte brut
print(response.headers)        # Headers de réponse

# GET avec paramètres
response = requests.get(
    "https://api.example.com/users",
    params={"page": 1, "limit": 10, "active": True}
)
# URL: https://api.example.com/users?page=1&limit=10&active=True

# POST avec JSON
response = requests.post(
    "https://api.example.com/users",
    json={"name": "John", "email": "john@example.com"}
)

# POST avec form data
response = requests.post(
    "https://api.example.com/login",
    data={"username": "admin", "password": "secret"}
)

# PUT
response = requests.put(
    "https://api.example.com/users/123",
    json={"name": "John Updated"}
)

# DELETE
response = requests.delete("https://api.example.com/users/123")
```

### Headers Personnalisés

```python
import requests

headers = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "MyApp/1.0"
}

response = requests.get(
    "https://api.example.com/protected",
    headers=headers
)
```

### Timeout et Gestion d'Erreurs

```python
import requests
from requests.exceptions import (
    RequestException,
    HTTPError,
    ConnectionError,
    Timeout
)

def safe_request(url, timeout=10):
    """Requête HTTP avec gestion d'erreurs complète."""
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()  # Lève HTTPError si status >= 400
        return response.json()

    except Timeout:
        print(f"Timeout: {url}")
        return None

    except ConnectionError:
        print(f"Erreur de connexion: {url}")
        return None

    except HTTPError as e:
        print(f"Erreur HTTP {e.response.status_code}: {e}")
        return None

    except RequestException as e:
        print(f"Erreur de requête: {e}")
        return None

# Utilisation
data = safe_request("https://api.example.com/data")
```

---

## 3. Sessions et Authentification

### Sessions (Réutilisation de Connexion)

```python
import requests

# Sans session (nouvelle connexion à chaque requête)
response1 = requests.get("https://api.example.com/users")
response2 = requests.get("https://api.example.com/posts")

# Avec session (réutilise la connexion)
session = requests.Session()
session.headers.update({
    "Authorization": "Bearer token",
    "Accept": "application/json"
})

response1 = session.get("https://api.example.com/users")
response2 = session.get("https://api.example.com/posts")

session.close()

# Avec context manager
with requests.Session() as session:
    session.headers.update({"Authorization": "Bearer token"})
    response = session.get("https://api.example.com/data")
```

### Authentification Basique

```python
import requests
from requests.auth import HTTPBasicAuth

# Méthode 1 : Tuple
response = requests.get(
    "https://api.example.com/data",
    auth=("username", "password")
)

# Méthode 2 : HTTPBasicAuth
response = requests.get(
    "https://api.example.com/data",
    auth=HTTPBasicAuth("username", "password")
)
```

### Authentification par Token

```python
import requests

# Bearer Token (JWT, OAuth2)
headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIs..."}
response = requests.get(
    "https://api.example.com/protected",
    headers=headers
)

# API Key dans header
headers = {"X-API-Key": "your-api-key-here"}
response = requests.get(
    "https://api.example.com/data",
    headers=headers
)

# API Key dans params
response = requests.get(
    "https://api.example.com/data",
    params={"api_key": "your-api-key-here"}
)
```

### OAuth2 Flow

```python
import requests

class OAuth2Client:
    """Client OAuth2 simple."""

    def __init__(self, client_id, client_secret, token_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.access_token = None
        self.session = requests.Session()

    def get_token(self):
        """Obtient un access token."""
        response = requests.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
        )
        response.raise_for_status()
        data = response.json()
        self.access_token = data["access_token"]
        self.session.headers.update({
            "Authorization": f"Bearer {self.access_token}"
        })

    def request(self, method, url, **kwargs):
        """Fait une requête authentifiée."""
        if not self.access_token:
            self.get_token()

        response = self.session.request(method, url, **kwargs)

        # Rafraîchir le token si expiré
        if response.status_code == 401:
            self.get_token()
            response = self.session.request(method, url, **kwargs)

        return response

# Utilisation
client = OAuth2Client(
    client_id="my-client-id",
    client_secret="my-secret",
    token_url="https://auth.example.com/oauth/token"
)

response = client.request("GET", "https://api.example.com/users")
```

---

## 4. Client API Robuste

### Classe Client Réutilisable

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any
import logging

class APIClient:
    """Client API générique avec retry et gestion d'erreurs."""

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 30,
        retries: int = 3
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

        # Configurer la session avec retry
        self.session = requests.Session()

        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Headers par défaut
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Effectue une requête HTTP."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        self.logger.debug(f"{method} {url}")

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                timeout=self.timeout,
                **kwargs
            )
            response.raise_for_status()

            if response.content:
                return response.json()
            return {}

        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP Error: {e.response.status_code} - {e.response.text}")
            raise

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, data: Dict) -> Dict:
        return self._request("POST", endpoint, data=data)

    def put(self, endpoint: str, data: Dict) -> Dict:
        return self._request("PUT", endpoint, data=data)

    def patch(self, endpoint: str, data: Dict) -> Dict:
        return self._request("PATCH", endpoint, data=data)

    def delete(self, endpoint: str) -> Dict:
        return self._request("DELETE", endpoint)

    def close(self):
        self.session.close()

# Utilisation
api = APIClient(
    base_url="https://api.example.com",
    api_key="your-token"
)

users = api.get("/users", params={"active": True})
new_user = api.post("/users", data={"name": "John"})
api.close()
```

### Pagination Automatique

```python
def paginate(client, endpoint, params=None, page_key="page", limit_key="limit", limit=100):
    """Itérateur pour la pagination automatique."""
    params = params or {}
    params[limit_key] = limit
    page = 1

    while True:
        params[page_key] = page
        response = client.get(endpoint, params=params)

        items = response.get("data", [])
        if not items:
            break

        yield from items

        # Vérifier s'il y a plus de pages
        if len(items) < limit:
            break

        page += 1

# Utilisation
for user in paginate(api, "/users", params={"active": True}):
    print(user["name"])
```

---

## 5. APIs Courantes en SysOps

### GitHub API

```python
import requests

class GitHubClient:
    """Client pour l'API GitHub."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        })

    def get_repos(self, org: str) -> list:
        """Liste les repos d'une organisation."""
        repos = []
        page = 1

        while True:
            response = self.session.get(
                f"{self.BASE_URL}/orgs/{org}/repos",
                params={"page": page, "per_page": 100}
            )
            response.raise_for_status()
            data = response.json()

            if not data:
                break

            repos.extend(data)
            page += 1

        return repos

    def create_issue(self, owner: str, repo: str, title: str, body: str) -> dict:
        """Crée une issue."""
        response = self.session.post(
            f"{self.BASE_URL}/repos/{owner}/{repo}/issues",
            json={"title": title, "body": body}
        )
        response.raise_for_status()
        return response.json()

# Utilisation
gh = GitHubClient("ghp_your_token_here")
repos = gh.get_repos("myorg")
```

### Prometheus API

```python
import requests
from datetime import datetime, timedelta

class PrometheusClient:
    """Client pour l'API Prometheus."""

    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def query(self, query: str) -> dict:
        """Exécute une requête PromQL."""
        response = requests.get(
            f"{self.url}/api/v1/query",
            params={"query": query}
        )
        response.raise_for_status()
        return response.json()

    def query_range(
        self,
        query: str,
        start: datetime,
        end: datetime,
        step: str = "15s"
    ) -> dict:
        """Requête sur une plage de temps."""
        response = requests.get(
            f"{self.url}/api/v1/query_range",
            params={
                "query": query,
                "start": start.timestamp(),
                "end": end.timestamp(),
                "step": step
            }
        )
        response.raise_for_status()
        return response.json()

    def get_alerts(self) -> list:
        """Récupère les alertes actives."""
        response = requests.get(f"{self.url}/api/v1/alerts")
        response.raise_for_status()
        return response.json()["data"]["alerts"]

# Utilisation
prom = PrometheusClient("http://prometheus:9090")

# CPU usage
result = prom.query('100 - (avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)')

# Historique mémoire
end = datetime.now()
start = end - timedelta(hours=1)
history = prom.query_range(
    'node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes * 100',
    start, end, "1m"
)
```

### Vault API

```python
import requests

class VaultClient:
    """Client pour HashiCorp Vault."""

    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["X-Vault-Token"] = token

    def get_secret(self, path: str) -> dict:
        """Lit un secret KV v2."""
        response = self.session.get(
            f"{self.url}/v1/secret/data/{path}"
        )
        response.raise_for_status()
        return response.json()["data"]["data"]

    def put_secret(self, path: str, data: dict) -> dict:
        """Écrit un secret KV v2."""
        response = self.session.post(
            f"{self.url}/v1/secret/data/{path}",
            json={"data": data}
        )
        response.raise_for_status()
        return response.json()

    def list_secrets(self, path: str) -> list:
        """Liste les secrets dans un path."""
        response = self.session.request(
            "LIST",
            f"{self.url}/v1/secret/metadata/{path}"
        )
        response.raise_for_status()
        return response.json()["data"]["keys"]

# Utilisation
vault = VaultClient("https://vault.example.com", "s.your-token")
db_creds = vault.get_secret("database/production")
print(db_creds["password"])
```

---

## 6. Upload de Fichiers

```python
import requests

# Upload simple
with open("document.pdf", "rb") as f:
    response = requests.post(
        "https://api.example.com/upload",
        files={"file": f}
    )

# Upload avec métadonnées
with open("image.png", "rb") as f:
    response = requests.post(
        "https://api.example.com/upload",
        files={"file": ("custom_name.png", f, "image/png")},
        data={"description": "My image"}
    )

# Upload multiple
files = [
    ("files", ("file1.txt", open("file1.txt", "rb"), "text/plain")),
    ("files", ("file2.txt", open("file2.txt", "rb"), "text/plain"))
]
response = requests.post("https://api.example.com/upload", files=files)
```

---

## 7. Webhooks et Callbacks

```python
import requests
import hmac
import hashlib
import json

def send_webhook(url: str, payload: dict, secret: str = None) -> bool:
    """Envoie un webhook avec signature optionnelle."""
    headers = {"Content-Type": "application/json"}

    body = json.dumps(payload)

    if secret:
        signature = hmac.new(
            secret.encode(),
            body.encode(),
            hashlib.sha256
        ).hexdigest()
        headers["X-Signature"] = f"sha256={signature}"

    try:
        response = requests.post(
            url,
            data=body,
            headers=headers,
            timeout=10
        )
        return response.status_code == 200
    except requests.RequestException:
        return False

# Envoyer une notification Slack
def send_slack_message(webhook_url: str, message: str, channel: str = None):
    """Envoie un message Slack via webhook."""
    payload = {"text": message}
    if channel:
        payload["channel"] = channel

    response = requests.post(webhook_url, json=payload)
    return response.status_code == 200

# Utilisation
send_slack_message(
    "https://hooks.slack.com/services/XXX/YYY/ZZZ",
    "Déploiement terminé avec succès!"
)
```

---

## Exercices Pratiques

### Exercice 1 : Monitoring API

```python
# Créer un script qui :
# - Interroge plusieurs APIs de santé
# - Mesure les temps de réponse
# - Envoie une alerte si un service est down
```

### Exercice 2 : Sync GitHub Issues

```python
# Créer un script qui :
# - Liste toutes les issues ouvertes d'un repo
# - Exporte en JSON/CSV
# - Supporte la pagination
```

### Exercice 3 : API Rate Limiter

```python
# Créer une classe qui :
# - Limite les requêtes à N par seconde
# - Gère les erreurs 429
# - Implémente le backoff exponentiel
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Toujours définir des timeouts
    - Utiliser des sessions pour réutiliser les connexions
    - Implémenter des retries avec backoff
    - Logger les requêtes et réponses
    - Ne jamais stocker les secrets dans le code

!!! warning "Sécurité"
    ```python
    # MAUVAIS
    api_key = "sk-12345"  # Secret dans le code!

    # BON
    import os
    api_key = os.environ.get("API_KEY")
    ```

---

## Voir Aussi

- [Module 10 - Programmation Réseau](10-reseau.md)
- [Module 12 - SSH & Automatisation](12-ssh.md)
- [Cheatsheet Bibliothèques](cheatsheet-libs.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 10 - Programmation Réseau](10-reseau.md) | [Module 12 - SSH & Automatisation Dist... →](12-ssh.md) |

[Retour au Programme](index.md){ .md-button }
