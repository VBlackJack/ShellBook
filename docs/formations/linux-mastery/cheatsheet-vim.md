---
tags:
  - formation
  - linux
  - vim
  - cheatsheet
  - editeur
---

# Cheatsheet Vim

Guide de référence rapide pour l'éditeur Vim.

---

## Modes

| Mode | Description | Accès |
|------|-------------|-------|
| **Normal** | Navigation, commandes | `Esc` |
| **Insert** | Saisie de texte | `i`, `a`, `o` |
| **Visual** | Sélection | `v`, `V`, `Ctrl+v` |
| **Command** | Commandes Ex | `:` |

---

## Navigation

### Mouvements de Base

```text
      k
      ↑
  h ← · → l
      ↓
      j
```

| Touche | Action |
|--------|--------|
| `h` | Gauche |
| `j` | Bas |
| `k` | Haut |
| `l` | Droite |

### Par Mots

| Touche | Action |
|--------|--------|
| `w` | Début du mot suivant |
| `W` | Début du MOT suivant (ignore ponctuation) |
| `b` | Début du mot précédent |
| `B` | Début du MOT précédent |
| `e` | Fin du mot courant/suivant |
| `E` | Fin du MOT courant/suivant |

### Par Lignes

| Touche | Action |
|--------|--------|
| `0` | Début de ligne |
| `^` | Premier caractère non-blanc |
| `$` | Fin de ligne |
| `g_` | Dernier caractère non-blanc |

### Par Écran

| Touche | Action |
|--------|--------|
| `H` | Haut de l'écran |
| `M` | Milieu de l'écran |
| `L` | Bas de l'écran |
| `Ctrl+f` | Page suivante |
| `Ctrl+b` | Page précédente |
| `Ctrl+d` | Demi-page bas |
| `Ctrl+u` | Demi-page haut |

### Par Fichier

| Touche | Action |
|--------|--------|
| `gg` | Début du fichier |
| `G` | Fin du fichier |
| `{n}G` ou `:{n}` | Aller à la ligne n |
| `%` | Parenthèse/crochet correspondant |

---

## Mode Insert

### Entrer en Mode Insert

| Touche | Action |
|--------|--------|
| `i` | Avant le curseur |
| `I` | Début de ligne |
| `a` | Après le curseur |
| `A` | Fin de ligne |
| `o` | Nouvelle ligne dessous |
| `O` | Nouvelle ligne dessus |
| `s` | Supprimer caractère + insert |
| `S` | Supprimer ligne + insert |

### Sortir du Mode Insert

| Touche | Action |
|--------|--------|
| `Esc` | Retour mode Normal |
| `Ctrl+c` | Retour mode Normal |
| `Ctrl+[` | Retour mode Normal |

---

## Édition

### Supprimer

| Touche | Action |
|--------|--------|
| `x` | Caractère sous le curseur |
| `X` | Caractère avant le curseur |
| `dw` | Jusqu'à fin du mot |
| `diw` | Mot entier (inner word) |
| `daw` | Mot entier + espace |
| `d$` ou `D` | Jusqu'à fin de ligne |
| `d0` | Jusqu'à début de ligne |
| `dd` | Ligne entière |
| `{n}dd` | n lignes |
| `d{motion}` | Selon mouvement |

### Copier (Yank)

| Touche | Action |
|--------|--------|
| `yw` | Mot |
| `yiw` | Mot entier |
| `y$` | Jusqu'à fin de ligne |
| `yy` ou `Y` | Ligne entière |
| `{n}yy` | n lignes |
| `y{motion}` | Selon mouvement |

### Coller (Paste)

| Touche | Action |
|--------|--------|
| `p` | Après le curseur/ligne |
| `P` | Avant le curseur/ligne |

### Modifier (Change)

| Touche | Action |
|--------|--------|
| `cw` | Changer jusqu'à fin du mot |
| `ciw` | Changer le mot entier |
| `c$` ou `C` | Changer jusqu'à fin de ligne |
| `cc` | Changer la ligne entière |
| `c{motion}` | Changer selon mouvement |

### Autres

| Touche | Action |
|--------|--------|
| `r{char}` | Remplacer un caractère |
| `R` | Mode remplacement |
| `~` | Inverser la casse |
| `u` | Annuler (undo) |
| `Ctrl+r` | Refaire (redo) |
| `.` | Répéter la dernière action |
| `J` | Joindre lignes |

---

## Mode Visual

### Sélection

| Touche | Action |
|--------|--------|
| `v` | Mode caractère |
| `V` | Mode ligne |
| `Ctrl+v` | Mode bloc (colonne) |
| `gv` | Re-sélectionner |

### Actions sur Sélection

| Touche | Action |
|--------|--------|
| `d` | Supprimer |
| `y` | Copier |
| `c` | Changer |
| `>` | Indenter |
| `<` | Désindenter |
| `=` | Auto-indenter |
| `u` | Minuscules |
| `U` | Majuscules |

---

## Recherche

| Touche | Action |
|--------|--------|
| `/pattern` | Rechercher vers le bas |
| `?pattern` | Rechercher vers le haut |
| `n` | Occurrence suivante |
| `N` | Occurrence précédente |
| `*` | Mot sous le curseur (suivant) |
| `#` | Mot sous le curseur (précédent) |
| `:noh` | Supprimer surbrillance |

### Recherche et Remplacement

```vim
" Syntaxe
:s/old/new/          " Première occurrence, ligne courante
:s/old/new/g         " Toutes occurrences, ligne courante
:%s/old/new/g        " Tout le fichier
:%s/old/new/gc       " Avec confirmation
:10,20s/old/new/g    " Lignes 10 à 20

" Flags
" g - global (toutes les occurrences)
" c - confirm (confirmation)
" i - insensible à la casse
" I - sensible à la casse
```

---

## Commandes Ex

### Fichiers

```vim
:w                   " Sauvegarder
:w fichier           " Sauvegarder sous
:q                   " Quitter
:q!                  " Quitter sans sauvegarder
:wq ou :x ou ZZ      " Sauvegarder et quitter
:e fichier           " Ouvrir un fichier
:e!                  " Recharger (ignorer modifs)
:bn                  " Buffer suivant
:bp                  " Buffer précédent
:bd                  " Fermer buffer
:ls                  " Lister buffers
```

### Fenêtres (Splits)

```vim
:sp fichier          " Split horizontal
:vsp fichier         " Split vertical
:new                 " Nouveau fichier horizontal
:vnew                " Nouveau fichier vertical
Ctrl+w h/j/k/l       " Naviguer entre fenêtres
Ctrl+w H/J/K/L       " Déplacer fenêtre
Ctrl+w =             " Égaliser tailles
Ctrl+w _             " Maximiser hauteur
Ctrl+w |             " Maximiser largeur
:close ou Ctrl+w c   " Fermer fenêtre
:only ou Ctrl+w o    " Fermer les autres
```

### Onglets

```vim
:tabnew              " Nouvel onglet
:tabnew fichier      " Ouvrir dans nouvel onglet
gt                   " Onglet suivant
gT                   " Onglet précédent
{n}gt                " Aller à l'onglet n
:tabclose            " Fermer onglet
:tabonly             " Fermer les autres onglets
```

---

## Text Objects

Utilisés avec `d`, `c`, `y`, `v` + `i` (inner) ou `a` (around)

| Objet | Description |
|-------|-------------|
| `w` | mot |
| `W` | MOT |
| `s` | phrase |
| `p` | paragraphe |
| `"` `'` `` ` `` | Guillemets |
| `(` `)` `b` | Parenthèses |
| `[` `]` | Crochets |
| `{` `}` `B` | Accolades |
| `<` `>` | Chevrons |
| `t` | Tag HTML/XML |

### Exemples

```vim
ciw     " Changer le mot
ci"     " Changer dans les guillemets
da(     " Supprimer avec les parenthèses
yi{     " Copier dans les accolades
vit     " Sélectionner dans le tag
```

---

## Macros

```vim
q{a-z}               " Commencer enregistrement (registre a-z)
q                    " Arrêter enregistrement
@{a-z}               " Exécuter macro
@@                   " Répéter dernière macro
{n}@{a-z}            " Exécuter n fois
```

---

## Registres

```vim
"{a-z}y{motion}      " Copier dans registre
"{a-z}p              " Coller depuis registre
:reg                 " Voir tous les registres
"+y                  " Copier dans presse-papier système
"+p                  " Coller depuis presse-papier
```

| Registre | Description |
|----------|-------------|
| `"` | Registre par défaut |
| `0` | Dernier yank |
| `1-9` | Dernières suppressions |
| `+` | Presse-papier système |
| `*` | Sélection X11 |
| `/` | Dernière recherche |
| `:` | Dernière commande |
| `.` | Dernier texte inséré |
| `%` | Nom du fichier courant |
| `_` | Trou noir (suppression silencieuse) |

---

## Marques

```vim
m{a-z}               " Créer marque locale
m{A-Z}               " Créer marque globale
'{a-z}               " Aller à la ligne de la marque
`{a-z}               " Aller à la position exacte
:marks               " Lister les marques
```

---

## Configuration (.vimrc)

```vim
" Basiques
set nocompatible     " Mode Vim (pas Vi)
set encoding=utf-8   " Encodage UTF-8
syntax on            " Coloration syntaxique
filetype plugin indent on

" Affichage
set number           " Numéros de ligne
set relativenumber   " Numéros relatifs
set cursorline       " Surligner ligne courante
set showmatch        " Surligner parenthèses
set wrap             " Retour à la ligne
set linebreak        " Couper aux mots

" Indentation
set tabstop=4        " Largeur tab
set shiftwidth=4     " Largeur indentation
set expandtab        " Espaces au lieu de tabs
set autoindent       " Indentation auto
set smartindent      " Indentation intelligente

" Recherche
set hlsearch         " Surligner résultats
set incsearch        " Recherche incrémentale
set ignorecase       " Insensible à la casse
set smartcase        " Sauf si majuscule

" Divers
set hidden           " Buffers cachés
set wildmenu         " Menu complétion
set clipboard=unnamedplus  " Presse-papier système

" Mappings
let mapleader = " "  " Leader = espace
nnoremap <leader>w :w<CR>
nnoremap <leader>q :q<CR>
nnoremap <C-h> <C-w>h
nnoremap <C-j> <C-w>j
nnoremap <C-k> <C-w>k
nnoremap <C-l> <C-w>l
```

---

## Aide

```vim
:help               " Aide générale
:help {topic}       " Aide sur un sujet
:help :w            " Aide sur commande :w
:help i_CTRL-N      " Aide mode insert Ctrl+N
K                   " Man page du mot sous curseur
```

---

**Retour au :** [Programme de la Formation](index.md)
