+++
title = "3 Homelabs Pour Apprendre l'Offensif 🖥️"
date = "2024-04-05T22:44:32+02:00"
author = "Hadrien"
keywords = ["homelab", "linux", "windows"]
description = "**3 Homelabs à faire pour apprendre le pentest Web et AD**"
showFullContent = false
readingTime = false
hideComments = false
color = "" #color from the theme settings
+++

# Pourquoi faire un homelab ?

Lors de déplacements (ou entre 2 cours de management 👀), il m'arrive de déployer des petits et moyens labs permettant de perfectionner mes connaissances.

Les homelabs sont un moyen de pouvoir tester des technologies et des concepts localement sans avoir à faire tourner un VPN vers HackTheBox ou d'autres plateformes.

Voici donc les différents labs que j'ai eu l'occasion de déployer afin d'apprendre de nouvelles compétences.

⚠️ _**Attention**, dans aucun contexte ces labs sont à déployer dans un environnement de production_

## 🌐 Lab 1 : OWASP Juice Shop

Le lab Juice Shop proposé par l'OWASP est une application web (à ne surtout pas déployer en prod), permettant d'apprendre le pentest web reprenant le top 10 des vulnérabilités par l'OWASP.

Déployable via conteneur Docker, cette application est basée sur des technologies souvent utilisées dans le monde du développement web :

**Frontend** : 
- Angular JS
- Material

**Backend** :
- NodeJS
- Express
- Sequelize
- Serveur NoSQL et SQL

Lien vers la documentation officielle : https://owasp.org/www-project-juice-shop

---

## 🖥 Lab 2 : Game of Active Directory

Côté Actice Directory, Orange Cyberdefense propose un lab intitulé "GOAD". 
Le but de ce laboratoire est de déployer un lab AD vulnérable prêt à être utilisé pour pratiquer et comprendre des attaques.

**4** versions du lab sont proposé en fonction de votre configuration hardware :
- **GOAD** : 5 vms, 2 forêts, 3 domaines (la version "full")
- **GOAD-Light** : 3 vms, 1 forêt, 2 domaines (la version "light")
- **SCCM** : 4 vms, 1 forêt, 1 domaine, avec Microsoft Configuration Manager installé
- **NHA** : Un défi avec 5 vms et 2 domaines.

Lien vers le repo github : https://github.com/Orange-Cyberdefense/GOAD

---

## 🖥 Lab 3 : PimpMyADLab

TCM Security propose un également un lab en 3 vms pour les petites configurations hardware.
- 1 DC et 2 Workstations W10 

L'installation de ce lab est également indiqué dans la documentation avec un script permettant d'automatiser les actions à réaliser :

Lien vers le repo github : https://github.com/Dewalt-arch/pimpmyadlab

---

## 🔍 Pour aller plus loin : Ajouter une approche 🔵 et 🔴 Team

Pour les labs AD, il est possible de rajouter Wazuh, un XDR + SIEM pouvant apporter un côté défense à vos labs. -> https://wazuh.com

Si vous voulez monter en compétences sur des outils d'infrastructure C2, il en existe plusieurs mais voici les 3 que j'utilise le plus souvent :
- Havoc C2 https://github.com/HavocFramework/Havoc
- Mythic https://github.com/its-a-feature/Mythic
- Sliver https://github.com/BishopFox/sliver

