$ErrorActionPreference = "Stop"

$TELEPORT_CA_CERT_PEM = "{{.caCertPEM}}"
$TELEPORT_CA_CERT_SHA1 = "{{.caCertSHA1}}"
$TELEPORT_CA_CERT_BLOB_BASE64 = "{{.caCertBase64}}"
$TELEPORT_PROXY_PUBLIC_ADDR = "{{.proxyPublicAddr}}"
$TELEPORT_PROVISION_TOKEN = "{{.provisionToken}}"
$TELEPORT_INTERNAL_RESOURCE_ID = "{{.internalResourceID}}"

$AD_USER_NAME="Teleport Service Account"
$SAM_ACCOUNT_NAME="svc-teleport"

$DOMAIN_NAME=(Get-ADDomain).DNSRoot
$DOMAIN_DN=$((Get-ADDomain).DistinguishedName)

# Generate a random password that meets the "Password must meet complexity requirements" security policy setting.
# Note: if the minimum complexity requirements have been changed from the Windows default, this part of the script may need to be modified.
Add-Type -AssemblyName 'System.Web'
do {
   $PASSWORD=[System.Web.Security.Membership]::GeneratePassword(15,1)
} until ($PASSWORD -match '\d')
$SECURE_STRING_PASSWORD=ConvertTo-SecureString $PASSWORD -AsPlainText -Force

New-ADUser -Name $AD_USER_NAME -SamAccountName $SAM_ACCOUNT_NAME -AccountPassword $SECURE_STRING_PASSWORD -Enabled $true


# Create the CDP/Teleport container.
# If the command fails with "New-ADObject : An attempt was made to add an object to the directory with a name that is already in use",
# it means the object already exists and you can move on to the next step.
New-ADObject -Name "Teleport" -Type "container" -Path "CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN"

# Gives Teleport the ability to create LDAP containers in the CDP container.
dsacls "CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN" /I:T /G "$($SAM_ACCOUNT_NAME):CC;container;"
# Gives Teleport the ability to create and delete cRLDistributionPoint objects in the CDP/Teleport container.
dsacls "CN=Teleport,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN" /I:T /G "$($SAM_ACCOUNT_NAME):CCDC;cRLDistributionPoint;"
# Gives Teleport the ability to write the certificateRevocationList property in the CDP/Teleport container.
dsacls "CN=Teleport,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN " /I:T /G "$($SAM_ACCOUNT_NAME):WP;certificateRevocationList;"
# Gives Teleport the ability to create and delete certificationAuthority objects in the NTAuthCertificates container.
dsacls "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN" /I:T /G "$($SAM_ACCOUNT_NAME):CCDC;certificationAuthority;"
# Gives Teleport the ability to write the cACertificate property in the NTAuthCertificates container.
dsacls "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN" /I:T /G "$($SAM_ACCOUNT_NAME):WP;cACertificate;"

$SAM_ACCOUNT_SID=(Get-ADUser -Identity $SAM_ACCOUNT_NAME).SID.Value


# Step 2/7. Prevent the service account from performing interactive logins

$BLOCK_GPO_NAME="Block teleport-svc Interactive Login"
New-GPO -Name $BLOCK_GPO_NAME | New-GPLink -Target $DOMAIN_DN

$DENY_SECURITY_TEMPLATE=@'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
[Privilege Rights]
SeDenyRemoteInteractiveLogonRight=*{0}
SeDenyInteractiveLogonRight=*{0}
'@ -f $SAM_ACCOUNT_SID


$BLOCK_POLICY_GUID=((Get-GPO -Name $BLOCK_GPO_NAME).Id.Guid).ToUpper()
$BLOCK_GPO_PATH="$env:SystemRoot\SYSVOL\sysvol\$DOMAIN_NAME\Policies\{$BLOCK_POLICY_GUID}\Machine\Microsoft\Windows NT\SecEdit"
New-Item -Type Directory -Path $BLOCK_GPO_PATH
New-Item -Path $BLOCK_GPO_PATH -Name "GptTmpl.inf" -ItemType "file" -Value $DENY_SECURITY_TEMPLATE


# Step 3/7. Configure a GPO to allow Teleport connections
$ACCESS_GPO_NAME="Teleport Access Policy"
New-GPO -Name $ACCESS_GPO_NAME | New-GPLink -Target $DOMAIN_DN


$CERT = [System.Convert]::FromBase64String($TELEPORT_CA_CERT_BLOB_BASE64)
Set-GPRegistryValue -Name $ACCESS_GPO_NAME -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates\Root\Certificates\$TELEPORT_CA_CERT_SHA1" -ValueName "Blob" -Type Binary -Value $CERT


Write-Output $TELEPORT_CA_CERT_PEM | Out-File -FilePath teleport.pem

certutil -dspublish -f teleport.pem RootCA
certutil -dspublish -f teleport.pem NTAuthCA
certutil -pulse

$ACCESS_SECURITY_TEMPLATE=@'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
[Service General Setting]
"SCardSvr",2,""
'@

$COMMENT_XML=@'
<?xml version='1.0' encoding='utf-8'?>
<policyComments xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://www.microsoft.com/GroupPolicy/CommentDefinitions">
  <policyNamespaces>
    <using prefix="ns0" namespace="Microsoft.Policies.TerminalServer"></using>
  </policyNamespaces>
  <comments>
    <admTemplate></admTemplate>
  </comments>
  <resources minRequiredRevision="1.0">
    <stringTable></stringTable>
  </resources>
</policyComments>
'@


$ACCESS_POLICY_GUID=((Get-GPO -Name $ACCESS_GPO_NAME).Id.Guid).ToUpper()
$ACCESS_GPO_PATH="$env:SystemRoot\SYSVOL\sysvol\$DOMAIN_NAME\Policies\{$ACCESS_POLICY_GUID}\Machine\Microsoft\Windows NT\SecEdit"
New-Item -Type Directory -Path $ACCESS_GPO_PATH
New-Item -Path $ACCESS_GPO_PATH -Name "GptTmpl.inf" -ItemType "file" -Value $ACCESS_SECURITY_TEMPLATE
New-Item -Path "$env:SystemRoot\SYSVOL\sysvol\$DOMAIN_NAME\Policies\{$ACCESS_POLICY_GUID}\Machine" -Name "comment.cmtx" -ItemType "file" -Value $COMMENT_XML

# Firewall
$FIREWALL_USER_MODE_IN_TCP = "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|"
Set-GPRegistryValue -Name $ACCESS_GPO_NAME -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall" -ValueName "PolicyVersion" -Type DWORD -Value 543
Set-GPRegistryValue -Name $ACCESS_GPO_NAME -Type String -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "RemoteDesktop-UserMode-In-TCP" -Value $FIREWALL_USER_MODE_IN_TCP


# Allow remote RDP connections
Set-GPRegistryValue -Name $ACCESS_GPO_NAME -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -Type DWORD -Value 0
Set-GPRegistryValue -Name $ACCESS_GPO_NAME -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "UserAuthentication" -Type DWORD -Value 0


# # Step 5/7. Export your LDAP CA certificate
certutil "-ca.cert" windows.der
certutil -encode windows.der windows.pem

gpupdate.exe /force

$CA_CERT_PEM = Get-Content -Path windows.pem
$CA_CERT_YAML = $CA_CERT_PEM | ForEach-Object { "        " + $_  } | Out-String


$NET_BIOS_NAME = (Get-ADDomain).NetBIOSName
$LDAP_USERNAME = "$NET_BIOS_NAME\$SAM_ACCOUNT_NAME"

$COMPUTER_NAME = (Resolve-DnsName -Type A $Env:COMPUTERNAME).Name
$COMPUTER_IP = (Resolve-DnsName -Type A $Env:COMPUTERNAME).Address
$LDAP_ADDR="$COMPUTER_IP" + ":636"

$DESKTOP_ACCESS_CONFIG_YAML=@'
teleport:
  auth_token: {0}
  auth_servers: [ {1} ]

auth_service:
  enabled: no
ssh_service:
  enabled: no
proxy_service:
  enabled: no

windows_desktop_service:
  enabled: yes
  ldap:
    addr:     '{2}'
    domain:   '{3}'
    username: '{4}'
    server_name: '{5}'
    insecure_skip_verify: false
    ldap_ca_cert: |
{6}
  discovery:
    base_dn: '*'
  labels:
    teleport.internal/resource-id: {7}
'@ -f $TELEPORT_PROVISION_TOKEN, $TELEPORT_PROXY_PUBLIC_ADDR, $LDAP_ADDR, $DOMAIN_NAME, $LDAP_USERNAME, $COMPUTER_NAME, $CA_CERT_YAML, $TELEPORT_INTERNAL_RESOURCE_ID

$OUTPUT=@'

Use the following teleport.yaml to start a Windows Desktop Service.
For a detailed configuration reference, see

https://goteleport.com/docs/desktop-access/reference/configuration/


{0}

'@ -f $DESKTOP_ACCESS_CONFIG_YAML

Write-Output $OUTPUT

# cleanup files that were created duing execution of this script
Remove-Item teleport.pem -Recurse
Remove-Item windows.der -Recurse
Remove-Item windows.pem -Recurse

