+++
title = "⚔️ Game of Active Directory - EP 1"
date = "2024-04-11T21:36:41+02:00"
author = "Hadrien"
authorTwitter = "hadrien_cat"
tags = ["homelab", "AD"]
description = "**Mise en place** et **début de l'énumération** du **lab GOAD-Light**,"
showFullContent = false
readingTime = true
hideComments = false
color = "" #color from the theme settings
+++

## 🏁 Introduction

Dans un précédent article, j’avais parlé brièvement d’un lab AD proposé sur github par Orange Cyberdefense intitulé “GOAD”. 

Je me suis donc donné l’objectif de déployer la version **light** afin de reprendre la main sur le sujet du pentest AD.

Ce post est donc le **premier d’une suite** partant de 0 jusqu’à devenir DA (Administrateur du domaine).

Malgré qu’un schéma soit disponible expliquant le contenu du lab et certaines informations pouvant fortement aider à sa compromission, je décide de le faire en mode “**blackbox**”.

La procédure d'installation se trouve ici => [Lien vers le repo officiel](https://github.com/Orange-Cyberdefense/GOAD)

## ⚙️ Installation

Ayant un ordinateur avec 16Go de RAM, je modifie le fichier de config contenant le paramétrage des VMs qui vont être déployés
=> [Lien vers le fichier de configuration](https://github.com/Orange-Cyberdefense/GOAD/blob/main/ad/GOAD-Light/providers/virtualbox/Vagrantfile)

``v.memory`` et ``v.vmx["memsize"]`` indiquent la quantité de RAM utilisée par les VMs, je réduis la quantité en passant de 4Go à 2Go.

```js
<SNIP>
  config.vm.provider "virtualbox" do |v|
    v.memory = 2000
    v.cpus = 2
  end

  config.vm.provider "vmware_desktop" do |v|
    v.vmx["memsize"] = "2000"
    v.vmx["numvcpus"] = "2"
  end
<SNIP>
```

Vérification de la configuration avec la commande : ✅

``./goad.sh -t check -l GOAD-Light -p virtualbox -m docker``

et installation avec : ✅

``./goad.sh -t install -l GOAD-Light -p virtualbox  -m docker``


## 🔍 Énumération

Dans mon cas, l'interface réseau utilisée pour le lab est la suivante : 

=> ``vboxnet0`` avec comme plage d'adresse : ``192.168.56.1/24``

```js
[Apr 11, 2024 - 22:34:29 (CEST)] exegol-goad-light /workspace # netexec smb 192.168.56.1/24 
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
```

=> Pour ne pas à réécrire les adresses, je les enregistre dans un fichier `scope.txt`

```js
[Apr 11, 2024 - 22:34:49 (CEST)] exegol-goad-light /workspace # nmap -iL scope.txt
Nmap scan report for 192.168.56.10
Host is up (0.00010s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
MAC Address: 08:00:27:15:B6:75 (Oracle VirtualBox virtual NIC)

Nmap scan report for 192.168.56.11
Host is up (0.000069s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
MAC Address: 08:00:27:17:8D:E7 (Oracle VirtualBox virtual NIC)

Nmap scan report for 192.168.56.22
Host is up (0.00010s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
MAC Address: 08:00:27:31:40:53 (Oracle VirtualBox virtual NIC)
```
Avec les ports ouverts, on peut très vite remarquer que nous avons :

- 2 DC (`192.168.56.10` et `192.168.56.11`)
- 1 Windows Server (`192.168.56.22`)


Suite au prochain post !