---
tags:
  - formation
  - python
  - tests
  - pytest
  - qualité
  - ci-cd
---

# Module 15 - Tests & Qualité du Code

Écrire des tests robustes et maintenir un code de qualité.

---

## Objectifs du Module

- Maîtriser pytest pour les tests
- Utiliser les mocks et fixtures
- Mesurer la couverture de code
- Automatiser les tests dans la CI/CD

---

## 1. Introduction à pytest

### Installation

```bash
pip install pytest pytest-cov pytest-mock
```

### Premier Test

```python
# test_basic.py
def add(a, b):
    return a + b

def test_add():
    assert add(1, 2) == 3
    assert add(-1, 1) == 0
    assert add(0, 0) == 0

def test_add_strings():
    assert add("Hello ", "World") == "Hello World"
```

### Exécuter les Tests

```bash
# Tous les tests
pytest

# Fichier spécifique
pytest test_basic.py

# Test spécifique
pytest test_basic.py::test_add

# Avec verbosité
pytest -v

# Afficher les prints
pytest -s

# Arrêter au premier échec
pytest -x

# Derniers tests échoués
pytest --lf
```

---

## 2. Organisation des Tests

### Structure de Projet

```text
project/
├── src/
│   ├── __init__.py
│   ├── server.py
│   └── utils.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py      # Fixtures partagées
│   ├── test_server.py
│   └── test_utils.py
├── pytest.ini
└── pyproject.toml
```

### Configuration pytest.ini

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
markers =
    slow: marks tests as slow
    integration: marks tests as integration tests
```

### Classes de Test

```python
# test_server.py
class TestServerConnection:
    """Tests pour la connexion serveur."""

    def test_connect_success(self):
        server = Server("localhost", 8080)
        assert server.connect() is True

    def test_connect_failure(self):
        server = Server("invalid", 9999)
        assert server.connect() is False

class TestServerCommands:
    """Tests pour les commandes serveur."""

    def test_ping(self):
        server = Server("localhost", 8080)
        server.connect()
        assert server.ping() == "pong"
```

---

## 3. Fixtures

### Fixtures de Base

```python
# conftest.py
import pytest

@pytest.fixture
def sample_data():
    """Données de test."""
    return {"name": "test", "value": 42}

@pytest.fixture
def temp_file(tmp_path):
    """Crée un fichier temporaire."""
    file_path = tmp_path / "test.txt"
    file_path.write_text("Hello World")
    return file_path

@pytest.fixture
def server():
    """Serveur de test."""
    srv = Server("localhost", 8080)
    srv.start()
    yield srv  # Le test s'exécute ici
    srv.stop()  # Cleanup après le test

# test_example.py
def test_with_data(sample_data):
    assert sample_data["name"] == "test"

def test_with_file(temp_file):
    assert temp_file.read_text() == "Hello World"

def test_server(server):
    assert server.is_running()
```

### Fixtures avec Paramètres

```python
@pytest.fixture
def database(request):
    """Base de données configurable."""
    db_type = getattr(request, "param", "sqlite")

    if db_type == "sqlite":
        db = SQLiteDB(":memory:")
    elif db_type == "postgres":
        db = PostgresDB("localhost", 5432)

    db.connect()
    yield db
    db.disconnect()

@pytest.mark.parametrize("database", ["sqlite", "postgres"], indirect=True)
def test_insert(database):
    database.insert({"id": 1, "name": "test"})
    assert database.count() == 1
```

### Fixtures de Scope

```python
@pytest.fixture(scope="module")
def expensive_resource():
    """Ressource créée une fois par module."""
    resource = create_expensive_resource()
    yield resource
    resource.cleanup()

@pytest.fixture(scope="session")
def docker_container():
    """Container Docker pour toute la session."""
    container = start_docker_container()
    yield container
    container.stop()

@pytest.fixture(scope="function")  # Défaut
def per_test_resource():
    """Nouvelle ressource pour chaque test."""
    return Resource()
```

---

## 4. Mocking

### Mock de Base

```python
from unittest.mock import Mock, patch, MagicMock

def test_mock_basic():
    # Créer un mock
    mock_service = Mock()
    mock_service.get_data.return_value = {"status": "ok"}

    result = mock_service.get_data()
    assert result == {"status": "ok"}
    mock_service.get_data.assert_called_once()

def test_mock_side_effect():
    mock_api = Mock()
    # Retourne différentes valeurs à chaque appel
    mock_api.fetch.side_effect = [
        {"page": 1},
        {"page": 2},
        StopIteration
    ]

    assert mock_api.fetch()["page"] == 1
    assert mock_api.fetch()["page"] == 2
```

### Patch Decorator

```python
from unittest.mock import patch
import requests

def fetch_user(user_id):
    response = requests.get(f"https://api.example.com/users/{user_id}")
    return response.json()

@patch("requests.get")
def test_fetch_user(mock_get):
    mock_get.return_value.json.return_value = {"id": 1, "name": "John"}

    result = fetch_user(1)

    assert result["name"] == "John"
    mock_get.assert_called_once_with("https://api.example.com/users/1")

# Context manager
def test_fetch_user_context():
    with patch("requests.get") as mock_get:
        mock_get.return_value.json.return_value = {"id": 1, "name": "John"}
        result = fetch_user(1)
        assert result["name"] == "John"
```

### pytest-mock

```python
import pytest

def test_with_mocker(mocker):
    """Utilise le plugin pytest-mock."""
    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data="data"))

    with open("file.txt") as f:
        content = f.read()

    assert content == "data"
    mock_open.assert_called_once_with("file.txt")

def test_spy(mocker):
    """Espionne un appel sans le remplacer."""
    spy = mocker.spy(some_module, "some_function")

    result = some_module.some_function(42)

    spy.assert_called_once_with(42)
    # La vraie fonction a été appelée
```

### Mock pour SSH/API

```python
import pytest
from unittest.mock import Mock, patch

class TestSSHClient:
    @pytest.fixture
    def mock_ssh(self, mocker):
        mock = mocker.patch("paramiko.SSHClient")
        instance = mock.return_value
        instance.exec_command.return_value = (
            Mock(),  # stdin
            Mock(read=Mock(return_value=b"output")),  # stdout
            Mock(read=Mock(return_value=b""))  # stderr
        )
        return instance

    def test_run_command(self, mock_ssh):
        client = SSHClient("host", "user", "pass")
        result = client.run("ls -la")

        assert "output" in result
        mock_ssh.exec_command.assert_called_once_with("ls -la")

class TestAPIClient:
    @pytest.fixture
    def mock_requests(self, mocker):
        mock = mocker.patch("requests.Session")
        return mock.return_value

    def test_get_users(self, mock_requests):
        mock_requests.get.return_value.json.return_value = [
            {"id": 1, "name": "John"}
        ]

        client = APIClient("https://api.example.com")
        users = client.get_users()

        assert len(users) == 1
        assert users[0]["name"] == "John"
```

---

## 5. Tests Paramétrés

```python
import pytest

@pytest.mark.parametrize("input,expected", [
    ("hello", "HELLO"),
    ("World", "WORLD"),
    ("PyThOn", "PYTHON"),
])
def test_upper(input, expected):
    assert input.upper() == expected

@pytest.mark.parametrize("host,port,expected", [
    ("localhost", 80, True),
    ("localhost", 443, True),
    ("invalid.host", 80, False),
])
def test_connectivity(host, port, expected):
    result = check_connection(host, port)
    assert result == expected

# Combinaisons multiples
@pytest.mark.parametrize("x", [1, 2])
@pytest.mark.parametrize("y", [10, 20])
def test_multiply(x, y):
    assert x * y in [10, 20, 20, 40]
```

---

## 6. Assertions et Exceptions

### Assertions Avancées

```python
import pytest

def test_assertions():
    # Égalité
    assert [1, 2, 3] == [1, 2, 3]

    # Inclusion
    assert "error" in "error message"
    assert 5 in [1, 2, 3, 4, 5]

    # Comparaisons
    assert 10 > 5
    assert 3.14 == pytest.approx(3.14159, rel=0.01)

    # Types
    assert isinstance([1, 2], list)

    # Truthiness
    assert bool([1, 2, 3])
    assert not bool([])
```

### Tester les Exceptions

```python
import pytest

def divide(a, b):
    if b == 0:
        raise ValueError("Division by zero")
    return a / b

def test_divide_by_zero():
    with pytest.raises(ValueError) as excinfo:
        divide(10, 0)

    assert "Division by zero" in str(excinfo.value)

def test_divide_by_zero_match():
    with pytest.raises(ValueError, match="Division by zero"):
        divide(10, 0)

def test_no_exception():
    # Vérifie qu'aucune exception n'est levée
    result = divide(10, 2)
    assert result == 5
```

### Warnings

```python
import pytest
import warnings

def deprecated_function():
    warnings.warn("This function is deprecated", DeprecationWarning)
    return True

def test_deprecation_warning():
    with pytest.warns(DeprecationWarning):
        deprecated_function()

def test_warning_message():
    with pytest.warns(DeprecationWarning, match="deprecated"):
        deprecated_function()
```

---

## 7. Markers

```python
import pytest

# Marquer un test comme lent
@pytest.mark.slow
def test_slow_operation():
    import time
    time.sleep(5)
    assert True

# Skip un test
@pytest.mark.skip(reason="Not implemented yet")
def test_future_feature():
    pass

# Skip conditionnel
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Linux only"
)
def test_linux_feature():
    pass

# Test attendu d'échouer
@pytest.mark.xfail(reason="Known bug #123")
def test_known_bug():
    assert False

# Test d'intégration
@pytest.mark.integration
def test_database_connection():
    db = connect_to_database()
    assert db.is_connected()

# Exécuter uniquement certains markers
# pytest -m "slow"
# pytest -m "not slow"
# pytest -m "integration and not slow"
```

---

## 8. Couverture de Code

### Installation et Utilisation

```bash
pip install pytest-cov
pytest --cov=src --cov-report=html
```

### Configuration .coveragerc

```ini
[run]
source = src
omit =
    */tests/*
    */__init__.py
    */migrations/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise NotImplementedError
    if __name__ == .__main__.:

[html]
directory = htmlcov
```

### Dans pyproject.toml

```toml
[tool.coverage.run]
source = ["src"]
omit = ["*/tests/*", "*/__init__.py"]

[tool.coverage.report]
fail_under = 80
show_missing = true
```

---

## 9. Tests d'Intégration

```python
import pytest
import docker
import time

class TestDockerIntegration:
    """Tests d'intégration avec Docker."""

    @pytest.fixture(scope="class")
    def postgres_container(self):
        """Lance un container PostgreSQL pour les tests."""
        client = docker.from_env()

        container = client.containers.run(
            "postgres:13",
            environment={
                "POSTGRES_USER": "test",
                "POSTGRES_PASSWORD": "test",
                "POSTGRES_DB": "testdb"
            },
            ports={"5432/tcp": 5433},
            detach=True
        )

        # Attendre que PostgreSQL soit prêt
        time.sleep(5)

        yield container

        container.stop()
        container.remove()

    def test_database_connection(self, postgres_container):
        import psycopg2

        conn = psycopg2.connect(
            host="localhost",
            port=5433,
            user="test",
            password="test",
            dbname="testdb"
        )

        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()

        assert result[0] == 1
        conn.close()
```

---

## 10. Qualité du Code

### Linting avec flake8

```bash
pip install flake8
flake8 src/ tests/
```

### Configuration .flake8

```ini
[flake8]
max-line-length = 100
exclude = .git,__pycache__,build,dist
ignore = E501,W503
per-file-ignores =
    __init__.py:F401
```

### Formatage avec black

```bash
pip install black
black src/ tests/
black --check src/  # Vérifier sans modifier
```

### Type Checking avec mypy

```bash
pip install mypy
mypy src/
```

### Configuration pyproject.toml

```toml
[tool.black]
line-length = 100
target-version = ['py39']
include = '\.pyi?$'

[tool.isort]
profile = "black"
line_length = 100

[tool.mypy]
python_version = "3.9"
warn_return_any = true
warn_unused_configs = true
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --cov=src --cov-report=term-missing"
```

---

## 11. CI/CD avec GitHub Actions

```yaml
# .github/workflows/tests.yml
name: Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.9', '3.10', '3.11']

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements-dev.txt

      - name: Lint with flake8
        run: flake8 src/ tests/

      - name: Check formatting with black
        run: black --check src/ tests/

      - name: Type check with mypy
        run: mypy src/

      - name: Test with pytest
        run: pytest --cov=src --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: coverage.xml
```

---

## 12. Tests SysOps

### Test de Script de Backup

```python
import pytest
from pathlib import Path
from backup_script import BackupManager

class TestBackupManager:
    @pytest.fixture
    def backup_manager(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "file1.txt").write_text("content1")
        (source / "file2.txt").write_text("content2")

        dest = tmp_path / "backup"
        dest.mkdir()

        return BackupManager(str(source), str(dest))

    def test_create_backup(self, backup_manager):
        backup_path = backup_manager.create_backup()

        assert Path(backup_path).exists()
        assert backup_path.endswith(".tar.gz")

    def test_restore_backup(self, backup_manager, tmp_path):
        backup_path = backup_manager.create_backup()
        restore_path = tmp_path / "restored"

        backup_manager.restore(backup_path, str(restore_path))

        assert (restore_path / "file1.txt").read_text() == "content1"
```

### Test de Connexion SSH

```python
import pytest
from ssh_client import SSHClient

class TestSSHClient:
    @pytest.fixture
    def mock_paramiko(self, mocker):
        mock = mocker.patch("paramiko.SSHClient")
        return mock.return_value

    def test_connect(self, mock_paramiko):
        client = SSHClient("host", "user", password="pass")
        client.connect()

        mock_paramiko.connect.assert_called_once_with(
            hostname="host",
            username="user",
            password="pass"
        )

    def test_run_command(self, mock_paramiko):
        # Setup mock
        stdout_mock = mocker.Mock()
        stdout_mock.read.return_value = b"output"
        stdout_mock.channel.recv_exit_status.return_value = 0

        mock_paramiko.exec_command.return_value = (
            mocker.Mock(),  # stdin
            stdout_mock,
            mocker.Mock(read=mocker.Mock(return_value=b""))
        )

        client = SSHClient("host", "user", password="pass")
        client.connect()
        result = client.run("ls -la")

        assert result.stdout == "output"
        assert result.exit_code == 0
```

---

## Exercices Pratiques

### Exercice 1 : Tests pour un Client API

```python
# Écrire des tests pour :
# - Authentification (succès/échec)
# - Requêtes GET/POST
# - Gestion des erreurs HTTP
# - Pagination
```

### Exercice 2 : Tests d'Intégration

```python
# Créer des tests d'intégration qui :
# - Lancent un container Docker
# - Exécutent des opérations CRUD
# - Vérifient les résultats
# - Nettoient après les tests
```

### Exercice 3 : Pipeline CI/CD

```yaml
# Créer un pipeline qui :
# - Lint le code
# - Exécute les tests unitaires
# - Exécute les tests d'intégration
# - Génère un rapport de couverture
# - Déploie si tous les tests passent
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Écrire des tests avant le code (TDD)
    - Un test = un concept
    - Utiliser des fixtures pour le setup
    - Mocker les dépendances externes
    - Viser 80%+ de couverture

!!! warning "Pièges Courants"
    - Tests trop couplés au code
    - Fixtures trop complexes
    - Oublier de tester les cas d'erreur
    - Tests qui dépendent de l'ordre d'exécution

---

## Voir Aussi

- [Module 14 - Cloud & AWS](14-cloud.md)
- [Programme de la formation](index.md)
- [Cheatsheet Bibliothèques](cheatsheet-libs.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 14 - Cloud & AWS avec Python](14-cloud.md) | [TP Final : Infrastructure Health Repo... →](16-tp-final.md) |

[Retour au Programme](index.md){ .md-button }
