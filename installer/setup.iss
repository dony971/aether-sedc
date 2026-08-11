; AETHER SEDC Installer for Windows
; Requires Inno Setup 6+ (https://jrsoftware.org/isdl.php)

#define MyAppName "AETHER SEDC"
#define MyAppVersion "1.1.2"
#define MyAppPublisher "Aether Team"
#define MyAppURL "https://github.com/dony971/aether-sedc"
#define MyAppExeName "aether.exe"

[Setup]
AppId={{B8F4A3D1-9E2C-4A7F-8B6D-1C3E5F7A9B0D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=.
OutputBaseFilename=AETHER-SEDC-{#MyAppVersion}-setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: checkablealone

[Files]
Source: "..\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; Optional: include additional assets
; Source: "..\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /f /im {#MyAppExeName} 2>nul"; Flags: runhidden

[Code]
function InitializeSetup: Boolean;
begin
  Result := True;
end;
