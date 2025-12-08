---
tags:
  - ai
  - project
  - python
  - formation
---

# Module 5 : Projet Final - Doc-Bot

Il est temps d'assembler les pièces. Vous allez construire `sb-bot`, l'assistant CLI de ShellBook.

## Cahier des Charges

Le script doit :
1.  **Scanner** récursivement le dossier `docs/` de ShellBook pour trouver les fichiers Markdown.
2.  **Indexer** le contenu dans une base vectorielle (ChromaDB) locale.
3.  **Lancer une boucle** interactive pour poser des questions.
4.  **Répondre** en utilisant un LLM (Ollama ou OpenAI) en citant la source.

## Étapes de Développement

### Étape 1 : Ingestion
Utilisez `glob` pour lister les `.md`. Lisez le contenu. Découpez-le en morceaux (chunks) de 1000 caractères (pour ne pas saturer le contexte).

### Étape 2 : Vectorisation
Stockez ces chunks dans ChromaDB. *Astuce : Persistez la DB sur disque pour ne pas ré-indexer à chaque lancement.*

### Étape 3 : La boucle de Chat
```python
while True:
    q = input("Question (ou exit): ")
    if q == "exit": break
    
    # 1. Recherche RAG
    context = search_chroma(q)
    
    # 2. Appel LLM
    answer = ask_llm(question=q, context=context)
    
    print(f"Bot: {answer}")
```

## Bonus Ops
*   Ajoutez un flag `--model` pour choisir entre `gpt-4` et `llama3`.
*   Conteneurisez le tout avec un `Dockerfile` multi-stage (Build vs Run).

---

## Exercice Pratique

!!! example "Exercice : Construction du Doc-Bot Complet"
    **Objectif** : Assembler tous les concepts appris pour créer un assistant de documentation intelligent et local.

    **Étapes** :
    1. Créer un fichier `sb-bot.py` qui scanne récursivement le dossier `docs/` et indexe les fichiers `.md` dans ChromaDB
    2. Implémenter le découpage en chunks de 1000 caractères pour optimiser le contexte
    3. Développer une boucle interactive qui utilise RAG + LLM pour répondre aux questions avec citation des sources

??? quote "Solution"
    ```python
    import chromadb
    from pathlib import Path
    from openai import OpenAI
    import argparse

    def chunk_text(text, size=1000):
        """Découpe le texte en morceaux de taille fixe"""
        return [text[i:i+size] for i in range(0, len(text), size)]

    def index_docs(docs_path, collection):
        """Indexe tous les fichiers markdown"""
        md_files = Path(docs_path).rglob("*.md")
        doc_id = 0

        for file in md_files:
            content = file.read_text(encoding='utf-8')
            chunks = chunk_text(content)

            for chunk in chunks:
                collection.add(
                    documents=[chunk],
                    metadatas=[{"source": str(file)}],
                    ids=[f"doc_{doc_id}"]
                )
                doc_id += 1

        print(f"Indexé {doc_id} chunks depuis {docs_path}")

    def chat_loop(collection, model="gpt-3.5-turbo"):
        """Boucle interactive de chat"""
        client = OpenAI(api_key="votre_clé")

        while True:
            question = input("\nQuestion (ou 'exit'): ")
            if question.lower() == 'exit':
                break

            # RAG: Recherche
            results = collection.query(
                query_texts=[question],
                n_results=3
            )

            context = "\n---\n".join(results['documents'][0])
            sources = results['metadatas'][0]

            # Génération
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": f"Contexte :\n{context}\n\nRéponds en citant les sources."},
                    {"role": "user", "content": question}
                ]
            )

            print(f"\nBot: {response.choices[0].message.content}")
            print(f"\nSources: {set([s['source'] for s in sources])}")

    if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument("--docs", default="./docs", help="Chemin vers docs/")
        parser.add_argument("--model", default="gpt-3.5-turbo", help="Modèle LLM")
        args = parser.parse_args()

        # Setup DB persistante
        client = chromadb.PersistentClient(path="./chroma_db")
        collection = client.get_or_create_collection("shellbook")

        # Indexation (commentez après le premier run)
        index_docs(args.docs, collection)

        # Lancement du chat
        chat_loop(collection, args.model)
    ```

---

Félicitations ! Vous avez construit un moteur de recherche sémantique privé. Vous êtes maintenant un **AI Engineer**.

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : RAG (Chat with your Data)](04-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
