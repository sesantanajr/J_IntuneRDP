## Jornada 365 | Intune RDP
# Função para garantir que o módulo necessário esteja instalado
function Ensure-Module {
    param (
        [string]$moduleName
    )
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser
        Import-Module $moduleName
    }
}

# Garantir que o módulo NetSecurity esteja disponível
Ensure-Module -moduleName "NetSecurity"

# Função para criar logs
function Write-Log {
    param (
        [string]$message,
        [string]$type = 'INFO'
    )
    $logPath = "C:\Intune_Script_Log.txt"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$type] $message"
    Add-Content -Path $logPath -Value $logMessage
}

# Verificação de Privilégios de Administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Este script precisa ser executado com privilégios de administrador. Solicitando elevação..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit 1
}

# Verifica se o dispositivo está registrado no Azure AD
try {
    $azureADInfo = (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
    if ($azureADInfo -ne $true) {
        Write-Log "Este dispositivo não está associado ao Azure AD." -type 'ERROR'
        Exit 1
    }
    Write-Log "Dispositivo associado ao Azure AD."
} catch {
    Write-Log "Erro ao verificar associação ao Azure AD: $_" -type 'ERROR'
    Exit 1
}

# Definindo listas de emails de forma centralizada para fácil modificação
$userListAdd = @(
    'user1@domain.com',
    'user2@domain.com'
)  # Substitua pelos e-mails desejados

$userListRemove = @(
    'user3@domain.com',
    'user4@domain.com'
)  # Substitua pelos e-mails desejados

# Função para adicionar usuários ao grupo local
function Add-UserToGroup {
    param (
        [string]$user,
        [string]$group
    )
    try {
        $userObject = "AzureAD\$user"
        if (-not (Get-LocalGroupMember -Group $group -Member $userObject -ErrorAction SilentlyContinue)) {
            Add-LocalGroupMember -Group $group -Member $userObject -ErrorAction Stop
            Write-Log "Usuário $user adicionado com sucesso ao grupo $group."
        } else {
            Write-Log "O usuário $user já é membro do grupo $group."
        }
    } catch {
        Write-Log "Falha ao adicionar o usuário $user: $_" -type 'ERROR'
    }
}

# Função para remover usuários do grupo local
function Remove-UserFromGroup {
    param (
        [string]$user,
        [string]$group
    )
    try {
        $userObject = "AzureAD\$user"
        if (Get-LocalGroupMember -Group $group -Member $userObject -ErrorAction SilentlyContinue) {
            Remove-LocalGroupMember -Group $group -Member $userObject -ErrorAction Stop
            Write-Log "Usuário $user removido com sucesso do grupo $group."
        } else {
            Write-Log "O usuário $user não é membro do grupo $group."
        }
    } catch {
        Write-Log "Falha ao remover o usuário $user: $_" -type 'ERROR'
    }
}

# Adiciona os usuários ao grupo 'Remote Desktop Users'
foreach ($user in $userListAdd) {
    Add-UserToGroup -user $user -group 'Remote Desktop Users'
}

# Remove os usuários do grupo 'Remote Desktop Users'
foreach ($user in $userListRemove) {
    Remove-UserFromGroup -user $user -group 'Remote Desktop Users'
}

# Função para habilitar regra de firewall
function Enable-FirewallRule {
    param (
        [string]$ruleName
    )
    try {
        $firewallRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
        if ($firewallRule.Enabled -eq 'False') {
            Enable-NetFirewallRule -DisplayName $ruleName
            Write-Log "Regra de firewall $ruleName habilitada com sucesso."
        } else {
            Write-Log "A regra de firewall já está habilitada: $ruleName"
        }
    } catch {
        Write-Log "Erro ao processar a regra de firewall $ruleName: $_" -type 'ERROR'
    }
}

# Verificar e habilitar as regras de firewall para RDP
$rdpRuleNames = @(
    "RemoteDesktop-UserMode-In-TCP",
    "RemoteDesktop-UserMode-In-UDP"
)

foreach ($ruleName in $rdpRuleNames) {
    Enable-FirewallRule -ruleName $ruleName
}

# Adicionar regra de firewall para permitir RDP em redes externas, se necessário
function Create-ExternalRDPFirewallRule {
    try {
        $rdpExternalRule = Get-NetFirewallRule -DisplayName "Allow RDP from external networks" -ErrorAction SilentlyContinue

        if ($null -eq $rdpExternalRule) {
            New-NetFirewallRule -DisplayName "Allow RDP from external networks" `
                                -Direction Inbound `
                                -Protocol TCP `
                                -LocalPort 3389 `
                                -Action Allow `
                                -RemoteAddress Any `
                                -Profile Any
            Write-Log "Regra de firewall para RDP externo criada e habilitada."
        } else {
            Write-Log "A regra de firewall para RDP externo já existe."
        }
    } catch {
        Write-Log "Erro ao criar a regra de firewall para RDP externo: $_" -type 'ERROR'
    }
}

# Chamar função para criar regra de firewall externa
Create-ExternalRDPFirewallRule

Write-Log "Configuração completa."
