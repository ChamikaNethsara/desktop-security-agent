#define MyAppName "Desktop Security Agent"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Desktop Security Agent Project"
#define MyAppExeName "SecurityAgent.exe"

; This script is located in the packaging directory.
#define ProjectRoot ".."

[Setup]
; Generate a GUID using Tools > Generate GUID in Inno Setup.
; Keep the same AppId for every future version of this application.
AppId={{6D49AFCD-5A16-45C5-A28B-D9D0F167272A}}

AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}

DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}

LicenseFile={#ProjectRoot}\LICENSE

; Assumes your PyInstaller build uses 64-bit Python.
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Use the project's existing multi-size ICO file.
SetupIconFile={#ProjectRoot}\resources\security_agent.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

; Output: installer/SecurityAgentSetup-0.1.0.exe
OutputDir={#ProjectRoot}\installer
OutputBaseFilename=SecurityAgentSetup-{#MyAppVersion}

Compression=lzma2
SolidCompression=yes
WizardStyle=modern

; The default installation is for all users.
PrivilegesRequired=admin

; Add useful version information to the installer executable.
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Desktop Security Agent Setup
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoVersion=0.1.0.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; \
    Description: "Create a desktop shortcut"; \
    GroupDescription: "Additional shortcuts:"; \
    Flags: unchecked

[Files]
; Install the entire PyInstaller onedir bundle.
; This includes the EXE, Python runtime, Qt libraries,
; bundled resources, and other collected dependencies.
Source: "{#ProjectRoot}\dist\SecurityAgent\*"; \
    DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; Install the MIT License alongside the application.
Source: "{#ProjectRoot}\LICENSE"; \
    DestDir: "{app}"; \
    DestName: "LICENSE"

[Icons]
; Start Menu shortcut.
Name: "{group}\{#MyAppName}"; \
    Filename: "{app}\{#MyAppExeName}"; \
    WorkingDir: "{app}"

; Optional desktop shortcut.
Name: "{autodesktop}\{#MyAppName}"; \
    Filename: "{app}\{#MyAppExeName}"; \
    WorkingDir: "{app}"; \
    Tasks: desktopicon

[Run]
; Offer to launch the application when installation finishes.
Filename: "{app}\{#MyAppExeName}"; \
    Description: "Launch {#MyAppName}"; \
    WorkingDir: "{app}"; \
    Flags: postinstall nowait skipifsilent
