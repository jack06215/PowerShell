function goto {
    param (
        $location
    )

    Switch ($location) {
        "monorepo" {
            Set-Location -Path "$HOME/Documents/Mycodespace/monorepo"
        }
        "jack06215" {
            Set-Location -Path "$HOME/Documents/Mycodespace/jack06215"
        }
        "nvim" {
            Set-Location -Path "$HOME/AppData/Local/nvim"
        }
        "powershell" {
            $location = Split-Path -Parent $PROFILE.CurrentUserAllHosts
            Set-Location -Path $location
        }
        default {
            Write-Error "Invalid location"
        }
    }
}

# starship configuration
$ENV:STARSHIP_CONFIG = "$HOME\.starship\starship.toml"
Invoke-Expression (&starship init powershell)

# Set Alias
Set-Alias g goto
Set-Alias pbcopy Set-Clipboard
Set-Alias -Name su -Value admin
