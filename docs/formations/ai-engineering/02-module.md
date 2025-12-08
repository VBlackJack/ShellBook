---
tags:
  - ai
  - prompting
  - json
  - formation
---

# Module 2 : Prompt Engineering & Structuration

Le "Prompt Engineering" n'est pas de la magie, c'est de la **programmation en langage naturel**.

## 1. Les Techniques de Prompting

### Zero-Shot (Naïf)
On pose la question direct.
> "Classe ce ticket support : 'Mon écran est bleu'."

### Few-Shot (Exemples)
On donne des exemples pour guider le style.
> "Tu es un classificateur de tickets.
> Exemple 1 : 'Le wifi est lent' -> RESEAU
> Exemple 2 : 'Mon clavier fume' -> MATERIEL
> Ticket : 'Mon écran est bleu' -> ?"

### Chain of Thought (CoT)
On force l'IA à réfléchir étape par étape (réduit les hallucinations).
> "Avant de répondre, analyse les causes possibles, puis conclus."

---

## 2. Structurer la sortie (JSON Mode)

Pour un Ops, du texte libre est inutile. On veut du JSON pour l'intégrer dans un script.

```python
response = client.chat.completions.create(
    model="gpt-3.5-turbo-0125",
    response_format={"type": "json_object"}, # Force le JSON
    messages=[
        {"role": "system", "content": "Tu es un extracteur de logs. Réponds TOUJOURS en JSON valide."},
        {"role": "user", "content": "Analyse ce log : 'Error 500 at /api/users caused by DB connection timeout'. Extrais le code, le path et la cause."}
    ]
)
```

**Résultat attendu :**
```json
{
  "code": 500,
  "path": "/api/users",
  "cause": "DB connection timeout"
}
```

## 3. TP : Le Générateur de Commits

**Objectif** : Créer un script `git-ai.py` qui :
1.  Fait un `git diff`.
2.  Envoie le diff à l'IA.
3.  Demande de générer un message de commit conventionnel (ex: `fix(api): handle timeout`).

*Indice* : Attention à la taille du diff ! S'il dépasse 4000 tokens, il faudra le tronquer.

---

## Exercice Pratique

!!! example "Exercice : Analyseur de Logs Structuré"
    **Objectif** : Créer un script qui analyse des logs serveur et extrait les informations importantes en JSON.

    **Étapes** :
    1. Créer un fichier `log_analyzer.py` qui lit un fichier de logs
    2. Utiliser l'API OpenAI avec `response_format={"type": "json_object"}` pour extraire : code HTTP, timestamp, IP source, et message d'erreur
    3. Tester avec différentes techniques : zero-shot, few-shot, et chain-of-thought

??? quote "Solution"
    ```python
    from openai import OpenAI
    import json

    client = OpenAI(api_key="votre_clé")

    log_entry = """
    2025-01-15 14:23:45 ERROR 192.168.1.100 - GET /api/users - 500 Internal Server Error: Database connection timeout
    """

    response = client.chat.completions.create(
        model="gpt-3.5-turbo-0125",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "Tu es un extracteur de logs. Réponds TOUJOURS en JSON valide avec les clés: timestamp, level, ip, method, path, code, error."},
            {"role": "user", "content": f"Analyse ce log : {log_entry}"}
        ]
    )

    result = json.loads(response.choices[0].message.content)
    print(json.dumps(result, indent=2))
    ```

---

## Navigation

| | |
|:---|---:|
| [← Module 1 : Les Fondations Modernes](01-module.md) | [Module 3 : Local AI & Ops →](03-module.md) |

[Retour au Programme](index.md){ .md-button }
