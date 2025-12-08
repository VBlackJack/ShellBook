---
tags:
  - embedded
  - yocto
  - linux
  - iot
  - bitbake
---

# Embedded Linux & Yocto Project

Le monde de l'embarqué (IoT, Automobile, Industriel) ne s'administre pas comme des serveurs Web. Ici, on construit son propre OS sur mesure.

## 1. Concepts de l'Embarqué

### Contraintes Spécifiques
*   **Ressources limitées** : CPU faible, peu de RAM (256 Mo), stockage Flash limité (eMMC).
*   **Temps Réel** : Nécessité parfois de patchs `PREEMPT_RT` pour garantir des temps de réponse déterministes.
*   **Robustesse** : Le système doit résister aux coupures de courant brutales (Filesystems Read-Only, A/B Partitioning pour les updates).
*   **Cross-Compilation** : On compile l'OS sur un PC puissant (x86_64) pour une cible faible (ARM, RISC-V).

### Bootloader Spécifique
Pas de GRUB ici. Le roi est **U-Boot**.
*   Initialise le hardware bas niveau (DDR, Clocks).
*   Charge le kernel et le Device Tree (DTB).

---

## 2. Yocto Project : La Factory d'OS

[Yocto](https://www.yoctoproject.org/) n'est pas une distribution Linux. C'est un outil pour **créer** une distribution Linux.

### Architecture
*   **Poky** : La distribution de référence.
*   **OpenEmbedded** : Le système de build sous-jacent.
*   **BitBake** : Le moteur d'exécution (l'équivalent de `make` mais pour tout un OS).

### Le Concept de "Recette" (Recipe)
Tout est défini dans des fichiers `.bb` (BitBake). Une recette dit :
1.  Où télécharger le code source (Git, Tarball).
2.  Comment le compiler (Autotools, CMake, Meson).
3.  Comment l'installer dans l'image finale.

### Les Layers (Couches)
Yocto fonctionne par couches empilées (`meta-*`).
*   `meta-poky` : Base du système.
*   `meta-raspberrypi` : Support matériel (BSP) pour RPi.
*   `meta-qt5` : Support du framework Qt.
*   `meta-mon-projet` : Vos propres applications et configurations.

> **Avantage** : Modularité totale. On ajoute une couche pour supporter une nouvelle carte électronique sans toucher au reste.

---

## 3. BitBake Cheat Sheet

```bash
# Initialiser l'environnement
source oe-init-build-env

# Compiler une image complète
bitbake core-image-minimal

# Compiler seulement un paquet
bitbake strace

# Nettoyer un paquet
bitbake -c clean strace

# Ouvrir un shell dans l'environnement de compilation (DevShell)
bitbake -c devshell strace

# Générer le SDK pour les développeurs d'app
bitbake core-image-minimal -c populate_sdk
```

## 4. Alternatives

*   **Buildroot** : Plus simple que Yocto, basé sur des Makefiles. Idéal pour des systèmes très petits et statiques.
*   **Debian/Ubuntu (binaire)** : Possible sur des cartes puissantes (RPi 4+), mais moins optimisé et plus lourd.
