---
tags:
  - ia
  - prompts
  - productivité
  - automation
---

# IA & Prompt Engineering pour SysOps

Guide pratique des prompts et meta-prompts pour l'administration système et le DevOps.

---

## Meta-Prompts Fondamentaux

### Définir un Rôle Expert

```
Tu es un ingénieur SysOps senior avec 15 ans d'expérience en environnements
de production critiques (Linux, Windows, Kubernetes). Tu privilégies :
- La sécurité et les bonnes pratiques
- Les solutions simples et maintenables
- La documentation claire
```

### Forcer un Format de Sortie

```
Réponds UNIQUEMENT avec :
- Un bloc de code exécutable
- Pas d'explications avant/après
- Commentaires inline si nécessaire
```

### Chaînage de Réflexion

```
Avant de répondre :
1. Analyse le contexte et les contraintes
2. Identifie les risques potentiels
3. Propose la solution la plus simple qui fonctionne
4. Explique les alternatives si pertinent
```

---

## Prompts SysOps par Catégorie

### Debugging & Troubleshooting

**Analyse de logs**
```
Analyse ces logs et identifie :
1. La cause racine probable
2. L'impact sur le système
3. Les actions correctives immédiates
4. Les mesures préventives

[COLLER LES LOGS]
```

**Debug service qui ne démarre pas**
```
Le service [NOM] ne démarre pas sur [OS].
Donne-moi une checklist de diagnostic dans l'ordre :
1. Vérifications basiques (syntaxe, permissions)
2. Dépendances (ports, fichiers, services)
3. Logs à consulter
4. Commandes de debug avancées
```

**Problème de performance**
```
Symptôme : [DESCRIPTION]
Système : [OS/VERSION]

Propose un arbre de décision pour diagnostiquer :
- CPU / Mémoire / IO / Réseau
Avec les commandes exactes à exécuter.
```

### Scripts & Automation

**Génération de script**
```
Écris un script [bash/python/powershell] qui :
- [OBJECTIF]
- Gère les erreurs proprement
- Log ses actions
- Est idempotent si possible

Contraintes :
- Compatible [VERSION OS]
- Sans dépendances externes / Avec [LIBS AUTORISÉES]
```

**Review de script existant**
```
Review ce script pour :
1. Bugs potentiels
2. Failles de sécurité (injection, permissions)
3. Améliorations de lisibilité
4. Optimisations performance

[COLLER LE SCRIPT]
```

**Conversion de script**
```
Convertis ce script [SOURCE] en [CIBLE] en :
- Gardant la même logique
- Utilisant les idiomes natifs du langage cible
- Améliorant si possible

[COLLER LE SCRIPT]
```

### Infrastructure & Configuration

**Génération de configuration**
```
Génère une configuration [nginx/apache/haproxy/...] pour :
- [CAS D'USAGE]
- Environnement : [prod/dev/staging]
- Contraintes sécurité : [LISTE]

Inclus les commentaires explicatifs.
```

**Audit de configuration**
```
Audite cette configuration pour :
1. Problèmes de sécurité
2. Erreurs de syntaxe
3. Optimisations possibles
4. Conformité [CIS/ANSSI/autre]

[COLLER LA CONFIG]
```

**Migration / Upgrade**
```
Je dois migrer de [VERSION_A] vers [VERSION_B] pour [SERVICE].
Environnement : [DESCRIPTION]

Fournis :
1. Checklist pré-migration
2. Procédure pas à pas
3. Points de rollback
4. Tests de validation post-migration
```

### Kubernetes & Conteneurs

**Génération de manifestes**
```
Génère les manifestes Kubernetes pour :
- Application : [DESCRIPTION]
- Replicas : [N]
- Resources : [CPU/MEM]
- Exposition : [ClusterIP/NodePort/Ingress]

Inclus : Deployment, Service, ConfigMap, et HPA si pertinent.
```

**Debug pod en erreur**
```
Pod en état [CrashLoopBackOff/Pending/Error].
Donne-moi la séquence de commandes kubectl pour diagnostiquer,
dans l'ordre de probabilité des causes.
```

**Dockerfile optimisé**
```
Crée un Dockerfile pour [LANGAGE/FRAMEWORK] qui :
- Utilise le multi-stage build
- Minimise la taille finale
- Tourne en non-root
- Inclut un healthcheck
```

### Sécurité & Conformité

**Hardening checklist**
```
Génère une checklist de hardening pour [OS/SERVICE] :
- Niveau : [basique/intermédiaire/avancé]
- Référentiel : [CIS/ANSSI/NIST]
- Format : commandes exécutables + vérification
```

**Analyse de vulnérabilité**
```
CVE-[NUMERO] affecte [SERVICE/PACKAGE].
Explique :
1. Impact et exploitabilité
2. Versions affectées
3. Mitigation immédiate
4. Correctif définitif
```

**Génération de règles firewall**
```
Génère les règles [iptables/nftables/ufw/Windows Firewall] pour :
- Autoriser : [LISTE SERVICES/PORTS]
- Bloquer : [LISTE]
- Logging : [oui/non]
- Format : script applicable
```

### Documentation

**Documentation technique**
```
Documente [SCRIPT/SERVICE/PROCÉDURE] avec :
- Synopsis / Description
- Prérequis
- Usage avec exemples
- Paramètres / Options
- Troubleshooting courant
```

**Procédure opérationnelle**
```
Écris une procédure pour [OPÉRATION] :
- Public : [junior/confirmé]
- Format : étapes numérotées avec commandes
- Inclure : vérifications, rollback, contacts escalade
```

---

## Patterns Avancés

### Itération Contrôlée

```
Je vais te donner du feedback. Après chaque itération :
1. Applique mes corrections
2. Explique ce que tu as changé
3. Attends mon prochain feedback

Première version : [DEMANDE INITIALE]
```

### Validation Croisée

```
Après avoir généré [CONFIG/SCRIPT/COMMANDE], vérifie toi-même :
1. Syntaxe valide ?
2. Effets de bord possibles ?
3. Compatible avec [CONTRAINTE] ?
4. Idempotent ?
```

### Mode Expert Critique

```
Joue l'avocat du diable sur cette solution.
Trouve les failles, les cas limites, les problèmes
qui pourraient survenir en production.
```

### Comparaison Structurée

```
Compare [OPTION_A] vs [OPTION_B] pour [CAS D'USAGE] :

| Critère | Option A | Option B |
|---------|----------|----------|
| Performance | ? | ? |
| Simplicité | ? | ? |
| Sécurité | ? | ? |
| Maintenabilité | ? | ? |

Recommandation finale avec justification.
```

---

## Techniques Renaud Dékode

Techniques de prompting issues de la chaîne [Renaud Dékode](https://www.youtube.com/@RenaudDekode) (Renaud Varoqueaux). Approche **agentique et systémique** : construire des systèmes de prompts plutôt que des formules isolées.

### Le Prompt "Système Identité"

Technique fondamentale pour personnaliser l'IA. À mettre dans les **Custom Instructions** ou en début de conversation.

```
Tu es un expert en [Domaine, ex: Administration Linux / DevOps].
Je souhaite que tu me répondes de façon respectueuse, intelligente et concise.
Je préfère que tu m'appelles [Prénom] et que tu ne me vouvoies pas.
Tu dois toujours répondre en français.
Si tu ne connais pas la réponse, dis-le clairement au lieu d'inventer.
```

**Effet** : Supprime le ton robotique, instaure une relation de "collègue expert".

### L'Optimiseur (Meta-Prompt)

Utiliser l'IA pour améliorer ses propres prompts avant d'exécuter la tâche.

```
Agis comme un expert en Prompt Engineering.
Voici mon prompt initial : "[Votre prompt basique]".
Analyse-le et propose-moi une version optimisée, plus structurée
(avec contexte, tâche, contraintes) pour maximiser la qualité du résultat.
Ne l'exécute pas tout de suite, donne-moi juste la version améliorée.
```

**Effet** : Transforme une demande floue en prompt structuré et performant.

### Le Collègue Développeur (Agentique)

Traiter l'IA comme un membre de l'équipe avec responsabilité complète.

```
Tu es mon collègue développeur Senior.
Ta mission est de travailler sur ce projet [Nom du projet].
Avant de proposer la moindre ligne de code, analyse l'ensemble des fichiers
du projet, la structure des dossiers et la documentation fournie.
Fais-moi d'abord un résumé de ce que tu as compris, puis propose un plan
d'action étape par étape pour implémenter la fonctionnalité [Nom de la feature].
```

**Effet** : Force l'analyse du contexte global avant de répondre, active le Chain of Thought.

### Le Dispatcher (Triage)

Créer des assistants polyvalents qui routent vers le bon "expert".

```
Tu agis comme un contrôleur de mission (Dispatcher).
Analyse la demande de l'utilisateur.
- Si la demande concerne l'infrastructure, active l'Agent "SysAdmin".
- Si la demande concerne le code, active l'Agent "Développeur".
- Si la demande concerne la sécurité, active l'Agent "SecOps".
Ne réponds pas à la question toi-même, route la demande vers le bon profil
et adopte sa persona pour la réponse.
```

**Effet** : Un seul fil de discussion capable de traiter des demandes variées avec expertise ciblée.

### Structure "Pistolet Chargé"

Les 4 éléments essentiels d'un prompt efficace :

| Élément | Description | Exemple |
|---------|-------------|---------|
| **Rôle** | Qui tu es | "Tu es un SRE senior" |
| **Contexte** | Où on est | "Infrastructure AWS, 50 serveurs" |
| **Tâche** | Ce qu'il faut faire | "Audite la config Terraform" |
| **Format** | Comment livrer | "Tableau avec criticité et remediation" |

```
[Rôle] Tu es un ingénieur SRE senior spécialisé Kubernetes.
[Contexte] Cluster de production avec 200 pods, pic de charge à 18h.
[Tâche] Analyse ce HPA et propose des optimisations.
[Format] Tableau avec : Paramètre actuel | Recommandation | Justification.
```

### Analyse avec Vérification

Pour l'analyse de fichiers/images, forcer la vérification avant action.

```
Regarde attentivement ce fichier/cette image.
Décris-moi en détail ce que tu vois et comment tu interprètes les données.
N'invente rien, base-toi uniquement sur les éléments fournis.
Si un élément est flou, demande-moi une clarification.
```

**Effet** : Réduit les hallucinations, ancre la réponse dans la réalité du fichier.

### Principes Clés Renaud Dékode

| Principe | Description |
|----------|-------------|
| **Agentic Mindset** | L'IA est un stagiaire/collègue, pas un moteur de recherche |
| **System Prompt** | Toujours utiliser les Custom Instructions |
| **Itération** | Ne jamais accepter la première réponse moyenne |
| **Auto-critique** | "Critique ta propre réponse et propose mieux" |
| **Connexion MCP** | Connecter l'IA aux outils (fichiers, API, CRM) |

---

## Anti-Patterns à Éviter

| Anti-Pattern | Problème | Alternative |
|--------------|----------|-------------|
| Prompt vague | Réponse générique | Contexte précis + contraintes |
| Pas de format demandé | Réponse verbeuse | Spécifier le format attendu |
| Copier-coller aveugle | Commandes dangereuses | Toujours relire et tester |
| Ignorer les warnings | Risques ignorés | Demander explication des risques |
| Un seul prompt | Solution sous-optimale | Itérer et affiner |

---

## Intégration Outils

### Claude Code (CLI)

```bash
# Mode non-interactif pour scripts
claude -p "Génère un script bash qui..." > script.sh

# Avec contexte fichier
claude "Explique ce script" < script.sh

# Review de diff
git diff | claude "Review ces changements"
```

### Workflows Typiques

**Debug rapide**
```bash
# Capturer erreur + contexte
journalctl -u nginx --since "5 min ago" | claude "Analyse cette erreur"
```

**Génération config**
```bash
# Générer puis valider
claude "Config nginx reverse proxy pour app:3000" > /tmp/nginx.conf
nginx -t -c /tmp/nginx.conf
```

**Documentation auto**
```bash
# Documenter un script existant
claude "Génère la doc markdown pour ce script" < mon-script.sh > README.md
```

---

## Prompts par Situation d'Urgence

### Incident Production

```
URGENT - Incident en cours :
- Symptôme : [DESCRIPTION]
- Impact : [USERS/SERVICES AFFECTÉS]
- Depuis : [DURÉE]

Donne-moi les 5 premières actions à faire MAINTENANT,
dans l'ordre, avec les commandes exactes.
```

### Rollback Nécessaire

```
Je dois rollback [SERVICE/DÉPLOIEMENT] immédiatement.
État actuel : [DESCRIPTION]
État cible : [VERSION/CONFIG PRÉCÉDENTE]

Procédure la plus rapide et sûre, étape par étape.
```

### Compromission Suspectée

```
Suspicion de compromission sur [SERVEUR].
Indices : [LISTE]

Checklist forensic immédiate :
1. Préservation des preuves
2. Isolation
3. Investigation
4. Ne PAS faire (pour ne pas altérer les preuves)
```

---

## Voir Aussi

- [Piliers DevOps](devops-pillars.md)
- [Git SysOps](../devops/git-sysops.md)
- [Outils IT](../devops/productivity-it-tools.md)
