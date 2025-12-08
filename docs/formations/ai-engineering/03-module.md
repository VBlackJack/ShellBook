---
tags:
  - ai
  - local
  - ollama
  - docker
  - formation
---

# Module 3 : Local AI & Ops

Le Cloud c'est bien, mais envoyer des données sensibles (mots de passe, code source privé) à OpenAI est souvent interdit.
La solution : **Local LLM**.

## 1. La Révolution Ollama

[Ollama](https://ollama.com/) est le "Docker de l'IA". Il permet de télécharger et runner des modèles avec une simple commande.

### Installation (Linux/WSL)
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Lancer un modèle
```bash
# Télécharge Llama3 (Meta) - environ 4GB
ollama run llama3

>>> Pourquoi Linux est mieux que Windows ?
```

## 2. API Locale

Ollama expose une API compatible (presque) avec OpenAI sur le port `11434`.

Dans votre code Python du Module 1, changez juste :
```python
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama", # Clé bidon requise
)

response = client.chat.completions.create(
    model="llama3", # Le nom du modèle local
    ...
)
```

## 3. Hardware : CPU vs GPU

*   **GPU (NVIDIA)** : Indispensable pour la vitesse. La mémoire VRAM est le facteur limitant.
    *   Modèle 7B (7 Milliards paramètres) ≈ 4-5 GB VRAM.
    *   Modèle 70B ≈ 40 GB VRAM (nécessite des cartes pro A100/H100).
*   **CPU** : Possible mais lent (1-3 mots/seconde). Ollama utilise `llama.cpp` pour optimiser ça.
*   **Quantization (Q4_K_M)** : Technique de compression. On réduit la précision des poids (de 16 bits à 4 bits) pour diviser la taille par 3, avec une perte de qualité minime.

## TP : Serveur d'Inférence Dockerisé

Créez un `docker-compose.yml` pour lancer Ollama + une WebUI (Open WebUI).

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]

  open-webui:
    image: ghcr.io/open-webui/open-webui:main
    ports:
      - "3000:8080"
    environment:
      - OLLAMA_BASE_URL=http://ollama:11434
```

---

## Exercice Pratique

!!! example "Exercice : Mise en Place d'une Stack IA Locale"
    **Objectif** : Déployer Ollama avec un modèle local et créer un script Python pour interagir avec ce modèle.

    **Étapes** :
    1. Installer Ollama et télécharger le modèle `llama3` ou `mistral`
    2. Créer un script Python `local_chat.py` qui utilise l'API locale d'Ollama
    3. Tester les performances CPU vs GPU si disponible et documenter les résultats (tokens/seconde)

??? quote "Solution"
    ```python
    from openai import OpenAI
    import time

    # Configuration pour Ollama local
    client = OpenAI(
        base_url="http://localhost:11434/v1",
        api_key="ollama"
    )

    def benchmark_model(model_name="llama3"):
        start = time.time()

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "Tu es un assistant système Linux."},
                {"role": "user", "content": "Explique en 50 mots comment fonctionne systemd."}
            ]
        )

        elapsed = time.time() - start
        answer = response.choices[0].message.content
        tokens = len(answer.split())

        print(f"Réponse : {answer}")
        print(f"\nPerformance : {tokens/elapsed:.2f} tokens/sec")

    if __name__ == "__main__":
        benchmark_model()
    ```
