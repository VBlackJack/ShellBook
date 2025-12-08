---
tags:
  - hacking
  - binary
  - exploit
  - buffer-overflow
  - reverse-engineering
---

# Introduction au Buffer Overflow

Comment les pirates transforment un crash de programme en exécution de code.

![Buffer Overflow Stack](../assets/infographics/security/buffer-overflow-stack.jpeg)

## 1. Le Concept

Imaginez un verre d'eau (le Buffer) de 20cl.
Si vous versez 30cl d'eau, ça déborde (Overflow).

En informatique, si un programme attend 8 caractères pour un mot de passe, mais que vous en envoyez 200 sans que le programme ne vérifie la taille :
1.  Les 8 premiers remplissent la variable "mot de passe".
2.  Les suivants écrasent la mémoire voisine.
3.  Si vous écrasez l'adresse de retour (**EIP**), vous contrôlez le flux d'exécution.

## 2. La Mémoire (Stack)

La pile (Stack) est organisée ainsi :

```
[ Buffer (Variable Locale) ]  <-- On écrit ici
[ EBP (Base Pointer) ]
[ EIP (Instruction Pointer) ] <-- Adresse de la prochaine instruction à exécuter
```

Le but est de remplir le Buffer jusqu'à atteindre **EIP** et le remplacer par l'adresse de notre code malveillant.

## 3. Le Workflow d'Exploitation

### Étape 1 : Fuzzing
Envoyer des chaînes de plus en plus longues jusqu'à ce que le programme crashe.
`python -c "print('A'*500)" | ./vuln_prog`
*Si "Segmentation Fault", c'est vulnérable.*

### Étape 2 : Trouver l'Offset
Combien de 'A' exactement faut-il pour atteindre EIP ?
On utilise un pattern unique (Metasploit `pattern_create.rb`).
`gdb` nous dira "EIP vaut 0x39644138", ce qui correspond à l'offset 142.

### Étape 3 : Contrôler EIP
On envoie `'A'*142 + 'B'*4`.
Si EIP vaut `42424242` (BBBB), on contrôle l'exécution !

### Étape 4 : Shellcode
On place notre Shellcode (le code qui lance `/bin/sh`) dans la mémoire.
On remplace les 'B' par l'adresse mémoire où se trouve notre Shellcode.

**Payload Final :**
`[ Padding (NOPs) ] + [ Shellcode ] + [ Adresse du Shellcode (dans EIP) ]`

## 4. Protections Modernes

Aujourd'hui, c'est plus dur :
*   **ASLR** : Les adresses changent à chaque démarrage (aléatoire).
*   **DEP / NX** : La Stack n'est pas exécutable (on ne peut pas lancer de shellcode).
*   **Canary** : Une valeur secrète placée avant EIP. Si elle est écrasée, le programme s'arrête avant le crash.

Pour contourner, on utilise le **ROP (Return Oriented Programming)**.
