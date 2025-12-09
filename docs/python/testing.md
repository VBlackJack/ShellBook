---
tags:
  - python
  - pytest
  - testing
  - infrastructure
---

# Tests & Qualité

Tests d'infrastructure et validation avec Pytest.

---

## Installation

```bash
pip install pytest pytest-cov pytest-xdist
```

---

## Pytest Basics

### Structure de Projet

```text
my_project/
├── src/
│   ├── __init__.py
│   ├── servers.py
│   └── network.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_servers.py
│   └── test_network.py
├── pytest.ini
└── requirements.txt
```

### Premier Test

```python
# tests/test_basic.py

def test_addition():
    assert 1 + 1 == 2

def test_string():
    hostname = "web-01"
    assert hostname.startswith("web")
    assert len(hostname) == 6
```

```bash
# Exécuter les tests
pytest

# Verbose
pytest -v

# Un fichier spécifique
pytest tests/test_basic.py

# Un test spécifique
pytest tests/test_basic.py::test_addition

# Avec coverage
pytest --cov=src --cov-report=html
```

---

## Fixtures

```python
# tests/conftest.py
import pytest


@pytest.fixture
def sample_server():
    """Fixture qui fournit un serveur de test."""
    return {
        "hostname": "test-server",
        "ip": "10.0.0.100",
        "port": 22
    }


@pytest.fixture
def server_list():
    """Fixture avec une liste de serveurs."""
    return [
        {"hostname": "web01", "ip": "10.0.0.10"},
        {"hostname": "web02", "ip": "10.0.0.11"},
        {"hostname": "db01", "ip": "10.0.0.20"},
    ]


@pytest.fixture(scope="module")
def ssh_connection():
    """Fixture avec setup/teardown."""
    # Setup
    connection = create_ssh_connection()
    yield connection
    # Teardown
    connection.close()
```

```python
# tests/test_servers.py

def test_server_hostname(sample_server):
    assert sample_server["hostname"] == "test-server"

def test_server_count(server_list):
    assert len(server_list) == 3

def test_filter_web_servers(server_list):
    web_servers = [s for s in server_list if s["hostname"].startswith("web")]
    assert len(web_servers) == 2
```

---

## Tests Paramétrés

```python
import pytest


@pytest.mark.parametrize("port,expected", [
    (22, True),
    (80, True),
    (443, True),
    (0, False),
    (-1, False),
    (65536, False),
])
def test_valid_port(port, expected):
    is_valid = 1 <= port <= 65535
    assert is_valid == expected


@pytest.mark.parametrize("hostname", [
    "web01",
    "web02",
    "db01",
])
def test_hostname_format(hostname):
    assert len(hostname) > 0
    assert hostname.isalnum() or "-" in hostname
```

---

## Tests d'Infrastructure

### Test de Connectivité

```python
# tests/test_network.py
import socket
import pytest


def check_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Vérifie si un port est ouvert."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except socket.error:
        return False


class TestNetworkConnectivity:
    """Tests de connectivité réseau."""

    @pytest.mark.parametrize("host,port", [
        ("google.com", 443),
        ("github.com", 443),
    ])
    def test_external_connectivity(self, host, port):
        """Vérifie la connectivité vers les services externes."""
        assert check_port(host, port), f"Cannot reach {host}:{port}"

    def test_dns_resolution(self):
        """Vérifie que le DNS fonctionne."""
        try:
            ip = socket.gethostbyname("google.com")
            assert ip is not None
        except socket.gaierror:
            pytest.fail("DNS resolution failed")
```

### Test de Configuration

```python
# tests/test_config.py
import pytest
import yaml
from pathlib import Path


@pytest.fixture
def config():
    """Charge la configuration."""
    config_path = Path("config.yaml")
    if not config_path.exists():
        pytest.skip("Config file not found")

    with open(config_path) as f:
        return yaml.safe_load(f)


class TestConfiguration:
    """Tests de validation de configuration."""

    def test_required_fields(self, config):
        """Vérifie les champs obligatoires."""
        required = ["database", "api", "logging"]
        for field in required:
            assert field in config, f"Missing required field: {field}"

    def test_database_config(self, config):
        """Vérifie la configuration base de données."""
        db = config.get("database", {})
        assert "host" in db
        assert "port" in db
        assert isinstance(db["port"], int)
        assert 1 <= db["port"] <= 65535

    def test_no_secrets_in_config(self, config):
        """Vérifie qu'il n'y a pas de secrets dans la config."""
        config_str = str(config).lower()
        forbidden = ["password=", "secret=", "api_key="]
        for pattern in forbidden:
            assert pattern not in config_str, f"Found secret pattern: {pattern}"
```

### Test de Fichiers et Permissions

```python
# tests/test_files.py
import pytest
import os
import stat
from pathlib import Path


class TestFileSystem:
    """Tests du système de fichiers."""

    @pytest.mark.parametrize("path", [
        "/etc/passwd",
        "/etc/group",
    ])
    def test_system_files_exist(self, path):
        """Vérifie que les fichiers système existent."""
        assert Path(path).exists(), f"Missing file: {path}"

    def test_ssh_key_permissions(self):
        """Vérifie les permissions de la clé SSH."""
        ssh_key = Path.home() / ".ssh" / "id_rsa"
        if not ssh_key.exists():
            pytest.skip("SSH key not found")

        mode = ssh_key.stat().st_mode
        # Doit être 600 (lecture/écriture owner uniquement)
        assert mode & 0o777 == 0o600, "SSH key permissions should be 600"

    def test_log_directory_writable(self, tmp_path):
        """Vérifie qu'on peut écrire dans le répertoire de logs."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test")
        assert log_file.exists()
        assert log_file.read_text() == "test"
```

---

## Mocking

```python
# tests/test_with_mocks.py
import pytest
from unittest.mock import Mock, patch, MagicMock


def get_server_status(hostname):
    """Fonction qui appelle une API externe."""
    import requests
    response = requests.get(f"https://api.example.com/servers/{hostname}")
    return response.json()


class TestWithMocks:
    """Tests avec mocking."""

    @patch('requests.get')
    def test_get_server_status(self, mock_get):
        """Test avec mock de requests."""
        # Configurer le mock
        mock_response = Mock()
        mock_response.json.return_value = {"status": "running", "cpu": 45}
        mock_get.return_value = mock_response

        # Appeler la fonction
        result = get_server_status("web01")

        # Vérifications
        assert result["status"] == "running"
        mock_get.assert_called_once_with("https://api.example.com/servers/web01")

    @patch('boto3.client')
    def test_aws_call(self, mock_boto_client):
        """Test avec mock de boto3."""
        # Configurer le mock
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{'InstanceId': 'i-123', 'State': {'Name': 'running'}}]
            }]
        }
        mock_boto_client.return_value = mock_ec2

        # Test
        import boto3
        ec2 = boto3.client('ec2')
        response = ec2.describe_instances()

        assert len(response['Reservations']) == 1
```

---

## Markers et Skip

```python
import pytest
import os


@pytest.mark.slow
def test_long_running_operation():
    """Test lent, marqué pour exécution conditionnelle."""
    import time
    time.sleep(5)
    assert True


@pytest.mark.integration
def test_database_connection():
    """Test d'intégration."""
    pass


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Skip in CI environment"
)
def test_local_only():
    """Test uniquement en local."""
    pass


@pytest.mark.skip(reason="Not implemented yet")
def test_future_feature():
    """Test à implémenter."""
    pass


def test_conditional_skip():
    """Skip conditionnel dans le test."""
    if not os.path.exists("/etc/myapp.conf"):
        pytest.skip("Config file not found")
    # Suite du test...
```

```ini
# pytest.ini
[pytest]
markers =
    slow: marks tests as slow
    integration: marks tests as integration tests

# Exécuter sans les tests lents
# pytest -m "not slow"

# Exécuter uniquement les tests d'intégration
# pytest -m integration
```

---

## Configuration Pytest

```ini
# pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
python_classes = Test*

# Options par défaut
addopts = -v --tb=short

# Markers
markers =
    slow: marks tests as slow
    integration: integration tests
    smoke: smoke tests

# Variables d'environnement
env =
    TESTING=true
    LOG_LEVEL=DEBUG
```

```toml
# pyproject.toml (alternative)
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "-v --tb=short"
markers = [
    "slow: marks tests as slow",
    "integration: integration tests",
]
```

---

## Test de Scripts Ops

```python
# tests/test_ops_script.py
import pytest
import subprocess
import sys


class TestOpsScript:
    """Tests pour un script d'administration."""

    def test_script_help(self):
        """Vérifie que --help fonctionne."""
        result = subprocess.run(
            [sys.executable, "scripts/manage_servers.py", "--help"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()

    def test_script_with_invalid_args(self):
        """Vérifie la gestion des erreurs."""
        result = subprocess.run(
            [sys.executable, "scripts/manage_servers.py", "--invalid"],
            capture_output=True,
            text=True
        )
        assert result.returncode != 0

    def test_script_dry_run(self):
        """Vérifie le mode dry-run."""
        result = subprocess.run(
            [sys.executable, "scripts/manage_servers.py", "--dry-run", "list"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "dry run" in result.stdout.lower() or "DRY RUN" in result.stdout
```

---

## Exécution

```bash
# Tous les tests
pytest

# Verbose
pytest -v

# Avec print() visible
pytest -s

# Parallèle (pytest-xdist)
pytest -n 4

# Stop au premier échec
pytest -x

# Coverage
pytest --cov=src --cov-report=html --cov-report=term

# Uniquement les tests qui ont échoué
pytest --lf

# Tests correspondant à un pattern
pytest -k "network or config"

# Exclure les tests lents
pytest -m "not slow"
```

---

## Voir Aussi

- [Fondamentaux](fundamentals.md) - Bases Python
- [API & Réseau](api-network.md) - Requests, SSH
