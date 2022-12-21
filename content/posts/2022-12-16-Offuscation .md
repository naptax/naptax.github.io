---
author: "Naptax"
title: "Anti-Debug 0x000: Offuscation - Part one -"
date: "2022-12-16"
tags: 
- malware
draft: true
---

<center>
<img width="600" src="/images/obfuscated.png">
</center>

**Hello**,

Le temps est venu de s'attaquer à un très gros morceau: les techniques d'Anti-Analyse. Et oui, les binaires sont des patients qui ne se laissent pas ausculter comme cela ...
En effet, les éditeurs commerciaux et les auteurs de malwares protègent leur binaire en y injectant un ou plusieurs mécanismes qui viennent complexifier et donc ralentir et diminuer le reverse de leur code,algo ou données. Ces techniques sont nombreuses et en perpétuelle évolution (comme toute situation "Le chat et la souris" ;-)

A ce stade, nous allons les diviser en 2 grandes catégories :
1. Les techniques qui viennent complexifier l'analyse statique : **Anti-Static**
2. Les techniques qui vienne complexifier l'analyse dynamique : **Anti-Debug**

Dans cette longue série nous allons commencer par l' **OFFUSCATION**

## Offuscation

Il existe aujourd'hui de nombreuses techniques pour complexifier le Reverse ou la simple compréhension d'un code binaire. Chaque acteur combine très souvent plusieurs moyens de protection.
Certaines techniques complexifient l'analyse statique (par exemple en induisant en erreur les décompilateurs tel qu'IDA, Ghidra, ...). D'autres ont pour objectif de ralentir l'analyse dynamique en utilisant des leurres qui viennent annihiler, voire parfois être offensif lors d'une exécutions sous Debuggeur. 

Afin de rentrer dans le sujet, nous allons commencer par les contre-mesures de base puis nous irons voir, billet par billet, du côté des techniques de pointe (croyez-moi, il y a des choses assez dingues !! )
Les classiques:

- Disassembly Desynchronization
- Pattern based obfuscation
- Constant unfolding
- Junk code insertion
- Stack-Based obfuscation

## Disassembly Desynchronization

Cette technique consiste à faire produire au désassembleur un code incorrect en plaçant des octets de données à des emplacements où ce dernier s'attend à trouver des octets d'instruction.
Par exemple, l'exécution ne doit pas nécessairement revenir à l'instruction suivant un CALL après la fin de la fonction; l'adresse de retour de la fonction peut être délibérément modifiée pendant l'exécution de cette dernière. Ainsi, il devient possible de placer des octets de données après CALL pour perturber le désassemblage puisque le flow n'y passera jamais. 

Prenons un exemple:

Voici le code assembleur **original**, c-à-d créé par l'auteur du malware (ici en MASM)

``` nasm
.code
main PROC
	xor eax, eax
	xor ebx, ebx
	call loc_bizarre
	db 'password',0
loc_bizarre:
	pop ebx
	INVOKE ExitProcess, eax
	ret
main ENDP
```

Notre cher IDA ayant beau être un **disassembler Flow-Oriented**, il reversera le code binaire par le code asm suivant:

``` nasm
.text:00401010 _main@0         proc near               ; CODE XREF: main()↑j
.text:00401010                 xor     eax, eax
.text:00401012                 xor     ebx, ebx
.text:00401014                 call    near ptr loc_40101E+1
.text:00401019 ; ---------------------------------------------------------------------------
.text:00401019                 push    6F6C6C65h       ; uExitCode
.text:0040101E
.text:0040101E loc_40101E:                             ; CODE XREF: main()+4↑p
.text:0040101E                 add     [ebx+50h], bl
.text:00401021                 call    _ExitProcess@4  ; ExitProcess(x)
.text:00401026 ; ---------------------------------------------------------------------------
.text:00401026                 retn
.text:00401026 _main@0         endp
```

Vous constatez qu'IDA a interprété les octets de la donnée 'password' située juste derrière notre CALL comme du code :-( L'auteur du malware est donc satisfait car il fait 2 choses en une:
1. Il masque sa data 
2. Il embrouille IDA et donc la personne qui Reverse

Heureusement il est possible avec IDA ou Ghidra de convertir en Data le code produit (et l'inverse également).
Pour cela on sélectionne notre octet de code douteux, puis on appuie sur **la touche D** pour lui dire **"Hey mec, c'est de la Data ces BYTES;-)"**.
On se retrouve ensuite avec un code désassemblé qui reproduit bien cette fois-ci le code original et ne masque plus cette précieuse chaine de caractères :

``` nasm
.text:00401010 _main@0         proc near               ; CODE XREF: main()↑j
.text:00401010
.text:00401010 ; FUNCTION CHUNK AT .text:0040107C SIZE 00000FC0 BYTES
.text:00401010
.text:00401010                 xor     eax, eax
.text:00401012                 xor     ebx, ebx
.text:00401014                 call    loc_401022
.text:00401014 ; ---------------------------------------------------------------------------
.text:00401019                 db 70h                  ; p
.text:0040101A                 db  61h ; a             ; a
.text:0040101B                 db 73h                  ; s
.text:0040101C                 db  73h ; s             ; s
.text:0040101D                 db 77h                  ; w
.text:0040101E                 db  6Fh ; o             ; o
.text:0040101F                 db 72h                  ; r
.text:00401020                 db  64h ; d             ; d
.text:00401021                 db 0
.text:00401022 ; ---------------------------------------------------------------------------
.text:00401022
.text:00401022 loc_401022:                             ; CODE XREF: main()+4↑p
.text:00401022                 pop     ebx
.text:00401023                 push    eax             ; uExitCode
.text:00401024                 call    _ExitProcess@4  ; ExitProcess(x)
.text:00401029 ; ---------------------------------------------------------------------------
.text:00401029                 retn
.text:00401029 _main@0         endp
```
### Que faut-il en comprendre ?

Et bien qu'en connaissant le fonctionnement interne d'IDA (on ne parlera même pas ici des autres ...) et bien les auteurs de malwares (ou toute personne qui souhaiterait complexifier le reverse de son binaire) peuvent occulter un premier niveau d'analyse.

Voyons maintenant quelques autres tricks de **Disassemby Desynchronization**.



<center>
<img width="200" src="/images/magiclamp.png">
</center>






<center>
<img width="600" src="/images/wip.png">
</center>