# UAC Bypass Tool

A Windows User Account Control (UAC) bypass utility written in Go.

## Overview

This tool exploits the Windows ComputerDefaults.exe application to bypass User Account Control (UAC) and execute applications with elevated privileges. It works by manipulating registry keys via direct syscalls to hijack the execution flow of a trusted Windows binary.

## Features
- Unhooks NTDLL
- Patches AMSI/ETW/DBGs 
- Bypasses UAC without prompting the user for elevation
- Executes specified applications with elevated privileges
- Includes cleanup functionality to restore registry settings
- Verifies elevation status of executed processes

## Demo
![uacdemo](https://github.com/user-attachments/assets/d850e832-b5e8-4c50-bc0f-5f900685db19)

## Usage

```

## to build the tool
export CGO_ENABLED=1
go build -o uac.exe cmd/main.go

## to run the tool
uac.exe [options]
```

### Options

- `-exec`: Path to the executable you want to run with elevated privileges
  - Default: `C:\Windows\System32\cmd.exe /c C:\Windows\System32\cmd,exe` (for system shell)

### Examples

Run with default settings (launches cmd.exe as admin)
```
uac.exe
```

Run a custom executable:
```
uac.exe -exec "C:\path\to\your\application.exe"
```

## Technical Details

The bypass works by:
1. Creating a registry key in the current user's hive
2. Setting up command execution parameters
3. Launching ComputerDefaults.exe, which inherits the elevated privileges
4. Optionally cleaning up registry modifications afterward

## Requirements

- Windows operating system
- Go 1.23.10 or higher
