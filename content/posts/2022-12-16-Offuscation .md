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

Le temps est venu de s'attaquer à un gros morceau: les techniques d'Anti-Analyse. Et oui, les binaires sont des patients qui ne se laissent pas occulter comme cela ...
En effet, les éditeurs commerciaux et les auteurs de malwares protègent leur binaire en y injectant un ou plusieurs mécanismes qui viennent complexifier et donc ralentir et diminuer le reverse de leur code,algo ou données. Ces techniques sont nombreuses et en perpétuelle évolution (comme toute situation "Le chat et la souris" ;-)

A ce stade, nous allons les diviser en 2 grandes catégories :
1. Les techniques qui viennent complexifier l'analyse statique : **Anti-Static**
2. Les techniques qui vienne complexifier l'analyse dynamique : **Anti-Debug**


