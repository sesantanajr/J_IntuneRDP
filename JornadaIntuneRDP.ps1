###################  JornadaIntuneRDP  ##################
# Configuração da Área de Trabalho Remota (RDP), Firewall e Gerenciamento de Permissões
#
# Versão: 6.1.0
# Autor: [Seu Nome]
# Data: 2024-08-23
#
# DESCRIÇÃO:
# Este script habilita a Área de Trabalho Remota (RDP), configura regras de firewall necessárias e gerencia
# a adição ou remoção de usuários nos grupos apropriados para acesso RDP, usando o UPN (email) diretamente.
# Compatível com Microsoft Intune, Windows 10 e 11.
#
# INSTRUÇÕES:
# - Execute este script com privilégios de administrador.
# - O script é compatível com ambientes gerenciados pelo Microsoft Intune.
# - Verifique o log para detalhes da execução.

# ========================== CONFIGURAÇÕES ==========================

$EnableRDP = $true                         # Habilitar Área de Trabalho Remota
$ConfigureFirewall = $true                 # Configurar regras de firewall para RDP
$AllowExternalRDP = $true                  # Permitir conexões RDP de redes externas
$AllowedIPs = @('0.0.0.0/0')               # Lista de endereços IP permitidos (use '0.0.0.0/0' para permitir todos)
$AddUsers = $true                          # Adicionar usuários ao grupo "Remote Desktop Users"
$RemoveUsers = $false                      # Remover usuários do grupo "Remote Desktop Users"
$UserListToAdd = @('gabriel.lima@lev.com.vc') # Usuários a adicionar
$UserListToRemove = @()                    # Usuários a remover

# Configurações de Log
$LogPath = "$env:ProgramData\JornadaIntuneRDP\Logs\JornadaIntuneRDP.log"
$LogRetentionDays = 30                     # Número de dias para reter os logs

# ========================== FUNÇÕES AUXILIARES ==========================

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp [$Level] $Message"
    Write-Output $logMessage
    Add-Content -Path $LogPath -Value $logMessage
}

function Ensure-AdminPrivileges {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Este script precisa ser executado com privilégios de administrador." -Level 'ERROR'
        Throw "Privilégios de administrador são necessários."
    } else {
        Write-Log "Privilégios de administrador confirmados."
    }
}

function Ensure-Module {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ModuleName
    )
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Log "Módulo '$ModuleName' não encontrado. Instalando..."
        Install-Module -Name $ModuleName -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        Write-Log "Módulo '$ModuleName' instalado com sucesso."
    }
    Import-Module -Name $ModuleName -ErrorAction Stop
    Write-Log "Módulo '$ModuleName' importado com sucesso."
}

function Ensure-Directories {
    try {
        $logDirectory = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path -Path $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
            Write-Log "Diretório de logs criado: $logDirectory"
        }
    } catch {
        Write-Log "Erro ao criar diretórios necessários: $_" -Level 'ERROR'
        Exit 1
    }
}

function Cleanup-OldLogs {
    try {
        if (Test-Path -Path $LogPath) {
            $logAge = (Get-Date) - (Get-Item $LogPath).LastWriteTime
            if ($logAge.Days -gt $LogRetentionDays) {
                Move-Item -Path $LogPath -Destination "$LogPath.$(Get-Date -Format 'yyyyMMddHHmmss').log" -Force
                Write-Log "Log antigo arquivado."
            }
        }
    } catch {
        Write-Log "Erro ao limpar logs antigos: $_" -Level 'ERROR'
    }
}

function Enable-RDP {
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\' -Name 'fDenyTSConnections' -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' -Name 'UserAuthentication' -Value 1 -ErrorAction Stop
        Write-Log "RDP e Autenticação no Nível de Rede (NLA) habilitados com sucesso."
    } catch {
        Write-Log "Erro ao habilitar RDP: $_" -Level 'ERROR'
        Throw $_
    }
}

function Configure-Firewall {
    try {
        Ensure-Module -ModuleName 'NetSecurity'

        $predefinedRules = @(
            'Remote Desktop - User Mode (TCP-In)',
            'Remote Desktop - User Mode (UDP-In)',
            'RemoteDesktop-UserMode-In-TCP',
            'RemoteDesktop-UserMode-In-UDP'
        )

        foreach ($ruleName in $predefinedRules) {
            $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if ($rule) {
                Enable-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                Write-Log "Regra de firewall '$ruleName' habilitada com sucesso."
            } else {
                $protocol = if ($ruleName -like '*TCP*') { 'TCP' } else { 'UDP' }
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol $protocol -LocalPort 3389 -Action Allow -Profile Any -ErrorAction Stop
                Write-Log "Regra de firewall '$ruleName' criada e habilitada com sucesso."
            }
        }

        if ($AllowExternalRDP) {
            $existingCustomRule = Get-NetFirewallRule -DisplayName 'Remote Desktop - Custom External Access' -ErrorAction SilentlyContinue
            if (-not $existingCustomRule) {
                New-NetFirewallRule -DisplayName 'Remote Desktop - Custom External Access' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -RemoteAddress $AllowedIPs -Profile Any -ErrorAction Stop
                Write-Log "Regra de firewall personalizada criada para acesso externo ao RDP."
            } else {
                # Atualizando as configurações da regra sem usar Set-NetFirewallAddressFilter
                Remove-NetFirewallRule -Name $existingCustomRule.Name -ErrorAction Stop
                New-NetFirewallRule -DisplayName 'Remote Desktop - Custom External Access' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -RemoteAddress $AllowedIPs -Profile Any -ErrorAction Stop
                Write-Log "Regra de firewall personalizada recriada com os endereços IP permitidos."
            }
        }
    } catch {
        Write-Log "Erro ao configurar o firewall: $_" -Level 'ERROR'
        Throw $_
    }
}

function Add-UserToRDPGroup {
    param (
        [string]$User
    )
    try {
        Write-Log "Tentando adicionar o usuário '$User' ao grupo 'Remote Desktop Users'..."
        Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $User -ErrorAction Stop
        Write-Log "Usuário '$User' adicionado ao grupo 'Remote Desktop Users' com sucesso."
    } catch {
        Write-Log "Erro ao adicionar o usuário '$User' ao grupo 'Remote Desktop Users': $_" -Level 'ERROR'
    }
}

function Manage-RDPUsers {
    try {
        Ensure-Module -ModuleName 'Microsoft.PowerShell.LocalAccounts'

        if ($AddUsers -and $UserListToAdd.Count -gt 0) {
            foreach ($user in $UserListToAdd) {
                Add-UserToRDPGroup -User $user
            }
        }

        if ($RemoveUsers -and $UserListToRemove.Count -gt 0) {
            foreach ($user in $UserListToRemove) {
                try {
                    Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $user -ErrorAction Stop
                    Write-Log "Usuário '$user' removido do grupo 'Remote Desktop Users' com sucesso."
                } catch {
                    Write-Log "Erro ao remover o usuário '$user' do grupo 'Remote Desktop Users': $_" -Level 'ERROR'
                }
            }
        }
    } catch {
        Write-Log "Erro ao gerenciar usuários do RDP: $_" -Level 'ERROR'
        Throw $_
    }
}

# ========================== EXECUÇÃO ==========================

try {
    Ensure-Directories
    Cleanup-OldLogs
    Write-Log "Iniciando execução do script JornadaIntuneRDP_v6.1.0.ps1"

    Ensure-AdminPrivileges

    if ($EnableRDP) {
        Enable-RDP
    }

    if ($ConfigureFirewall) {
        Configure-Firewall
    }

    if ($AddUsers -or $RemoveUsers) {
        Manage-RDPUsers
    }

    Write-Log "Execução do script concluída com sucesso."
} catch {
    Write-Log "Execução do script finalizada com erros: $_" -Level 'ERROR'
    Exit 1
}
