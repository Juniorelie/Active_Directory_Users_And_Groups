param (
$domainName = "konexio.eu", 
$fichiercsv = "C:\Users\Administrateur\Downloads\TSSR8_OUetGroupe.csv",
$OUprincipal = "presence" 
)

# Import du module Active Directory
Import-Module ActiveDirectory

# Chargement du CSV
$users = Import-Csv "$fichiercsv"


$listnom = $domainName.split(".")
# Domaine racine
$domainDN = "DC=$($listnom[0]), DC=$($listnom[1])"


# Création de l'OU principale
New-ADOrganizationalUnit -Name "$OUprincipal" -Path $domainDN -ProtectedFromAccidentalDeletion $false
Write-Host "OU '$OUprincipal' créée."

#Créer les dossiers(directories) pour chacque groupe sous c:\partage
$basePath = "C:\partage"
if (-not (Test-Path $basePath)) {
    New-Item -Path $basePath -ItemType Directory
}

foreach ($user in $users) {
    $prenom = $user.Prénom
    $nom = $user.Nom
    $ouName = $user.OU
    $groupe = $user.Groupe
    if (-not (Get-ADGroup -Filter "Name -eq '$groupe'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -GroupScope DomainLocal -Name $groupe
        #Créer le dossier pour le groupe $groupe
        $groupePath = "$basePath\$groupe"
        if (-not (Test-Path $groupePath)) {
            New-Item -Path $groupePath -ItemType Directory
        } 
        # Permissions NTFS
        $acl = Get-Acl $groupePath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $groupe, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $groupePath -AclObject $acl
        Write-Host "🔐 Droits accordés à $groupe"
        # Partage réseau
        if (-not (Get-SmbShare -Name $groupe -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name $groupe -Path $groupePath -FullAccess $groupe
            Write-Host "🌐 Partage créé : \$(hostname)$groupe"
        }
    }
# Construction du nom complet et identifiant
    $fullName = "$prenom $nom"
    $samAccountName = ($prenom.Substring(0,1) + $nom).ToLower()

    # Chemin complet de l'OU utilisateur
    $ouPath = "OU=$ouName,OU=$OUprincipal,$domainDN" 

    # Création de la sous OU
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ouName -Path "OU=$OUprincipal,$domainDN" -ProtectedFromAccidentalDeletion $false
        Write-Host "OU '$ouName' créée sous '$OUprincipal'."
    }

    # Création de l'utilisateur
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $fullName `
                   -DisplayName "$nom $prenom" `
                   -GivenName $prenom `
                   -Surname $nom `
                   -SamAccountName $samAccountName `
                   -UserPrincipalName "$samAccountName@$domainName" `
                   -Path $ouPath `
                   -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) `
                   -ChangePasswordAtLogon $true `
                   -Enabled $true

        Write-Host "Utilisateur $fullName créé dans $ouName."
    } else {
        Write-Host "Utilisateur $samAccountName existe déjà, création ignorée."
    }
    Add-ADGroupMember -Identity $groupe -Members $samAccountName
}