---
tags:
  - formation
  - ai
  - python
  - setup
  - llm
---

# Module 1 : Les Fondations Modernes

Oubliez les réseaux de neurones complexes. Aujourd'hui, l'IA est une **API** ou un **Binaire** que l'on appelle.

## 1. Concepts Clés (Le Jargon)

Avant de coder, il faut parler le langage.

### LLM (Large Language Model)
C'est le cerveau (ex: GPT-4, Claude 3, Llama 3). C'est un moteur de prédiction statistique : il devine le mot suivant le plus probable.

### Tokens
L'IA ne lit pas des mots, mais des "syllabes" numériques.
*   1000 tokens ≈ 750 mots.
*   **Context Window** : La mémoire à court terme du modèle (ex: 128k tokens). Si vous dépassez, il oublie le début.

### Température (0.0 à 2.0)
Le réglage de la "créativité".
*   `0.0` : Déterministe (Code, Math). Répondra toujours la même chose.
*   `0.7` : Standard (Chat).
*   `1.0+` : Créatif (Poésie, Idéation). Peut halluciner.

---

## 2. Setup Environnement Python

En tant qu'Ops, on isole toujours nos environnements.

```powershell
# Création du dossier projet
mkdir ai-lab
cd ai-lab

# Création de l'environnement virtuel
python -m venv venv

# Activation
.\venv\Scripts\Activate.ps1

# Installation des libs de base
pip install openai python-dotenv
```

## 3. Premier Appel API (Hello World)

Nous allons utiliser le format standard (compatible OpenAI, Mistral, LocalAI).

Créez un fichier `.env` pour votre clé API :
```ini
OPENAI_API_KEY=sk-proj-xxxxxxxx...
```

Créez `hello_ai.py` :
```python
import os
from dotenv import load_dotenv
from openai import OpenAI

# Charge les variables d'env
load_dotenv()

# Initialisation du client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# L'appel
response = client.chat.completions.create(
    model="gpt-3.5-turbo", # Ou "gpt-4o"
    messages=[
        {"role": "system", "content": "Tu es un expert SysAdmin."},
        {"role": "user", "content": "Explique la commande 'chmod 777' en une phrase, comme si j'avais 5 ans."}
    ],
    temperature=0.0,
)

print(response.choices[0].message.content)
```

**Exercice** : Exécutez ce script et modifiez le "System Prompt" pour que l'IA réponde comme un pirate.

---

## Navigation

| | |
|:---|---:|
| [← Programme](index.md) | [Module 2 : Prompt Engineering & Struc... →](02-module.md) |

[Retour au Programme](index.md){ .md-button }
