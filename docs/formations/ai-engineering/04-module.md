---
tags:
  - ai
  - rag
  - embeddings
  - vector-db
  - formation
---

# Module 4 : RAG (Chat with your Data)

Les LLM ont deux défauts majeurs :
1.  **Hallucination** : Ils inventent quand ils ne savent pas.
2.  **Obsolescence** : Ils ne connaissent pas vos données privées ni l'actualité récente.

La solution n'est pas de réentraîner le modèle (trop cher), mais de lui donner le contexte : le **RAG** (Retrieval-Augmented Generation).

## 1. Le Principe du RAG

C'est comme donner un livre ouvert à un étudiant pendant l'examen.
1.  **Question** : "Comment configurer Postfix ?"
2.  **Recherche** : Le script cherche dans votre documentation les paragraphes qui parlent de Postfix.
3.  **Prompt Augmenté** : On envoie à l'IA :
    > "Voici de la documentation : [Contenu du fichier postfix.md...]
    > Réponds à la question : 'Comment configurer Postfix ?' en utilisant UNIQUEMENT la documentation ci-dessus."

## 2. La Magie des Embeddings

Comment l'ordinateur sait que "Postfix" est proche de "SMTP" ? Grâce aux **Vecteurs**.

Un modèle d'Embedding (ex: `text-embedding-3-small`) transforme un texte en une liste de nombres (coordonnées GPS dans un espace sémantique).

*   "Roi" : `[0.9, 0.1, ...]`
*   "Reine" : `[0.85, 0.1, ...]` (Proche)
*   "Banane" : `[0.1, 0.9, ...]` (Loin)

## 3. Vector Database (ChromaDB)

Nous allons utiliser `chromadb` (librairie Python locale) pour stocker ces vecteurs.

### Workflow Python

```python
import chromadb
from chromadb.utils import embedding_functions

# 1. Setup DB (en mémoire pour le test)
chroma_client = chromadb.Client()
collection = chroma_client.create_collection(name="shellbook_docs")

# 2. Ajout de documents (Simulation)
collection.add(
    documents=["Postfix est un serveur MTA...", "Nginx est un serveur Web..."],
    ids=["doc1", "doc2"]
)

# 3. Recherche sémantique
results = collection.query(
    query_texts=["Comment envoyer des emails ?"], # Notez qu'on ne dit pas 'Postfix'
    n_results=1
)

print(results['documents'])
# Output probable : ["Postfix est un serveur MTA..."]
```

Le moteur a compris que "envoyer des emails" est sémantiquement lié à "MTA" et "Postfix". C'est ça, la puissance du RAG.

---

## Exercice Pratique

!!! example "Exercice : Créer un Assistant de Documentation"
    **Objectif** : Construire un système RAG simple qui répond aux questions sur une documentation technique.

    **Étapes** :
    1. Créer un fichier `rag_demo.py` avec ChromaDB pour indexer 3-5 documents markdown
    2. Implémenter une fonction de recherche sémantique qui retourne les documents pertinents
    3. Intégrer avec un LLM pour générer une réponse basée sur le contexte trouvé

??? quote "Solution"
    ```python
    import chromadb
    from openai import OpenAI

    # Setup ChromaDB
    client_db = chromadb.Client()
    collection = client_db.create_collection(name="docs")

    # Indexation de documents
    docs = [
        "Ansible est un outil d'automatisation IT qui utilise YAML pour décrire les tâches.",
        "Docker permet de conteneuriser des applications avec des images légères.",
        "Kubernetes orchestre des conteneurs Docker en production avec des pods et services."
    ]
    collection.add(
        documents=docs,
        ids=[f"doc{i}" for i in range(len(docs))]
    )

    # Fonction RAG
    def ask_rag(question):
        # 1. Recherche sémantique
        results = collection.query(
            query_texts=[question],
            n_results=2
        )
        context = "\n".join(results['documents'][0])

        # 2. Génération de réponse
        llm_client = OpenAI(api_key="votre_clé")
        response = llm_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": f"Réponds en utilisant UNIQUEMENT ce contexte :\n{context}"},
                {"role": "user", "content": question}
            ]
        )

        return response.choices[0].message.content

    # Test
    answer = ask_rag("Comment automatiser le déploiement ?")
    print(answer)
    ```
