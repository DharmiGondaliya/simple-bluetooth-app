# setup-directory.ps1
# PowerShell script to set up directory with proper permissions on Windows Server

param(
    [Parameter(Mandatory=$true)]
    [string]$DirectoryPath,
    
    [Parameter(Mandatory=$false)]
    [string]$Description = ""
)

try {
    Write-Host "Setting up directory: $DirectoryPath"
    
    # Verify directory exists
    if (-not (Test-Path -Path $DirectoryPath)) {
        Write-Error "Directory does not exist: $DirectoryPath"
        exit 1
    }
    
    # Get current user
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "Current user: $currentUser"
    
    # Set permissions (modify as needed based on your security requirements)
    $acl = Get-Acl $DirectoryPath
    
    # Grant full control to administrators
    $administratorsGroup = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $administratorsGroup,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($adminRule)
    
    # Grant modify rights to the current user (Node.js process user)
    $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $currentUser,
        "Modify",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($userRule)
    
    # Apply the ACL
    Set-Acl -Path $DirectoryPath -AclObject $acl
    Write-Host "✓ Permissions set successfully"
    
    # Create a metadata file if description provided
    if ($Description -ne "") {
        $metaFile = Join-Path -Path $DirectoryPath -ChildPath ".directory-info.txt"
        $metadata = @"
Directory: $DirectoryPath
Created: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Description: $Description
Created by: $currentUser
"@
        Set-Content -Path $metaFile -Value $metadata
        Write-Host "✓ Metadata file created"
    }
    
    # Log the operation
    $logDir = Split-Path -Parent $PSScriptRoot
    $logFile = Join-Path -Path $logDir -ChildPath "logs\directory-setup.log"
    $logDir = Split-Path -Parent $logFile
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Directory created: $DirectoryPath - User: $currentUser"
    Add-Content -Path $logFile -Value $logEntry
    Write-Host "✓ Operation logged"
    
    Write-Host "SUCCESS: Directory setup complete"
    exit 0
    
} catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    exit 1
}