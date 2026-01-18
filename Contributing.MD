# Contributing to Custodian-HT

Thank you for your interest in contributing to Custodian-HT! This document provides guidelines and information for contributors.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [How to Contribute](#how-to-contribute)
4. [Development Guidelines](#development-guidelines)
5. [Pull Request Process](#pull-request-process)
6. [Reporting Issues](#reporting-issues)
7. [Feature Requests](#feature-requests)
8. [Style Guide](#style-guide)

---

## Code of Conduct

This project follows a Code of Conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

---

## Getting Started

### Prerequisites

- PowerShell 5.1 or PowerShell 7.x
- Git
- A code editor (VS Code with PowerShell extension recommended)
- Windows 10/11 or Windows Server for testing

### Setting Up Development Environment

1. **Fork the repository**
   ```bash
   # Fork via GitHub UI, then clone your fork
   git clone https://github.com/YOUR-USERNAME/Custodian-HT.git
   cd Custodian-HT
   ```

2. **Add upstream remote**
   ```bash
   git remote add upstream https://github.com/yourusername/Custodian-HT.git
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Install dependencies**
   ```powershell
   .\Initialize-CustodianHT.ps1
   ```

---

## How to Contribute

### Types of Contributions

We welcome:

- **Bug fixes** - Fix issues in existing functionality
- **New features** - Add new capabilities
- **Documentation** - Improve or expand documentation
- **Hunt playbooks** - Add new threat hunting scenarios
- **Analysis integrations** - Add support for new forensic tools
- **OSINT sources** - Add new threat intelligence sources
- **Tests** - Add or improve testing coverage

### Contribution Areas

| Area | Description | Difficulty |
|------|-------------|------------|
| Bug fixes | Fix reported issues | Easy-Medium |
| Documentation | Improve guides and docs | Easy |
| New collection modules | Add artifact collectors | Medium |
| Hunt playbooks | Create hunting scenarios | Medium |
| Tool integrations | Integrate external tools | Medium-Hard |
| Remote capabilities | Enhance remote hunting | Hard |
| Core architecture | Modify core systems | Hard |

---

## Development Guidelines

### Project Structure

```
Custodian-HT/
├── Custodian-HTLauncher.ps1    # Main entry point
├── Custodian-HT.psm1           # Root module (imports all sub-modules)
├── Initialize-CustodianHT.ps1  # Setup script
├── Modules/                    # PowerShell modules
│   ├── CustodianCore.psm1      # Core utilities
│   ├── CustodianNetwork.psm1   # Network collection
│   ├── CustodianSystem.psm1    # System artifacts
│   └── ...
├── Config/                     # Configuration files
├── Tools/                      # External tools
├── Scripts/                    # Deployment scripts
├── Output/                     # Collection output
└── docs/                       # Documentation
```

### Module Guidelines

When creating or modifying modules:

1. **Follow naming convention**: `Custodian*.psm1`
2. **Include module manifest**: Use `.psd1` for production modules
3. **Export functions explicitly**: Use `Export-ModuleMember`
4. **Add help comments**: Use PowerShell comment-based help

Example function structure:

```powershell
function Get-CustodianExample {
    <#
    .SYNOPSIS
        Brief description of the function.
    
    .DESCRIPTION
        Detailed description of what the function does.
    
    .PARAMETER InputPath
        Description of the parameter.
    
    .EXAMPLE
        Get-CustodianExample -InputPath "C:\Evidence"
        
        Example description.
    
    .OUTPUTS
        Description of output objects.
    
    .NOTES
        Author: Your Name
        Date: 2026-01-18
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$InputPath,
        
        [Parameter()]
        [string]$OutputPath = (Get-CustodianPath -PathType "Triage")
    )
    
    begin {
        Write-Verbose "Starting Get-CustodianExample"
    }
    
    process {
        try {
            # Implementation
        }
        catch {
            Write-Error "Failed: $_"
        }
    }
    
    end {
        Write-Verbose "Completed Get-CustodianExample"
    }
}
```

### Testing Guidelines

1. **Test locally first**: Verify on your own system
2. **Test in VM**: Use a test VM for destructive operations
3. **Test remote features**: Use lab environment for remote testing
4. **Document test cases**: Note what you tested in the PR

### Security Considerations

- **Never commit credentials or API keys**
- **Sanitize output** in examples and documentation
- **Consider privilege levels** - mark admin-required functions
- **Validate all input** - especially paths and user input
- **Handle errors gracefully** - don't expose sensitive details

---

## Pull Request Process

### Before Submitting

1. **Sync with upstream**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Test your changes**
   ```powershell
   # Import and test
   Import-Module .\Custodian-HT.psm1 -Force
   # Run affected functions
   ```

3. **Update documentation** if needed

4. **Update CHANGELOG.md** with your changes

### Submitting a Pull Request

1. Push your branch to your fork
   ```bash
   git push origin feature/your-feature-name
   ```

2. Open a Pull Request on GitHub

3. Fill out the PR template:
   ```markdown
   ## Description
   Brief description of changes.
   
   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Documentation
   - [ ] Other (describe)
   
   ## Testing
   Describe how you tested the changes.
   
   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Comments added for complex logic
   - [ ] Documentation updated
   - [ ] No sensitive data in code
   ```

### Review Process

1. Maintainers will review your PR
2. Address any requested changes
3. Once approved, your PR will be merged

---

## Reporting Issues

### Bug Reports

Use the [Bug Report template](https://github.com/yourusername/Custodian-HT/issues/new?template=bug_report.md) and include:

- **Description**: Clear description of the bug
- **Steps to Reproduce**: Numbered steps to reproduce
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**:
  - OS version
  - PowerShell version (`$PSVersionTable`)
  - Custodian-HT version
- **Error Messages**: Full error text
- **Screenshots**: If applicable

Example:
```markdown
## Description
Get-CustodianNetworkConnections fails when UDP flag is used.

## Steps to Reproduce
1. Open Custodian-HT
2. Select Collection Modules
3. Select Network Collection
4. Function fails with error

## Expected Behavior
UDP connections should be collected along with TCP.

## Actual Behavior
Error: "Cannot bind parameter 'IncludeUDP'"

## Environment
- Windows 11 22H2
- PowerShell 5.1.22621.2506
- Custodian-HT v2.2.18

## Error Message
```
Get-CustodianNetworkConnections : Cannot bind parameter 'IncludeUDP'...
```
```

### Security Issues

For security vulnerabilities, please email security@yourdomain.com instead of opening a public issue.

---

## Feature Requests

Use the [Feature Request template](https://github.com/yourusername/Custodian-HT/issues/new?template=feature_request.md) and include:

- **Problem**: What problem does this solve?
- **Solution**: Describe the proposed solution
- **Alternatives**: Other solutions considered
- **Use Case**: Real-world scenario where this helps

---

## Style Guide

### PowerShell Style

Follow the [PowerShell Practice and Style Guide](https://poshcode.gitbook.io/powershell-practice-and-style/):

1. **Use approved verbs**: `Get-`, `Set-`, `New-`, `Remove-`, `Invoke-`
2. **Use PascalCase** for function names
3. **Use full cmdlet names**: `Where-Object` not `?`
4. **Use meaningful variable names**: `$networkConnections` not `$nc`
5. **Add help comments** for all public functions
6. **Use `[CmdletBinding()]`** for advanced functions
7. **Validate parameters** with `[ValidateScript()]`, `[ValidateSet()]`

### Code Examples

**Good:**
```powershell
function Get-CustodianNetworkConnections {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Get-CustodianPath -PathType "Triage"),
        
        [Parameter()]
        [switch]$IncludeUDP
    )
    
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
    
    if ($IncludeUDP) {
        $udpConnections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        $connections += $udpConnections
    }
    
    return $connections
}
```

**Avoid:**
```powershell
function getConnections($p, $u) {
    $c = Get-NetTCPConnection | ? { $_.State -eq 'Established' }
    if($u) { $c += Get-NetUDPEndpoint }
    $c
}
```

### Documentation Style

- Use Markdown for all documentation
- Include code examples with syntax highlighting
- Add table of contents for long documents
- Keep line length reasonable (~100 chars)

### Commit Messages

Use conventional commits:

```
type(scope): description

feat(playbooks): add ransomware detection playbook
fix(network): handle null DNS cache entries
docs(readme): update installation instructions
refactor(core): simplify path resolution logic
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

---

## Questions?

- Open a [Discussion](https://github.com/yourusername/Custodian-HT/discussions)
- Check existing [Issues](https://github.com/yourusername/Custodian-HT/issues)

Thank you for contributing to Custodian-HT! 🛡️

---

*Custodian-HT - RootGuard Cyber Defence*