; Night Tech Shield installer - Inno Setup 6.3 or newer (https://jrsoftware.org/isinfo.php)
; Build with ..\build.ps1 rather than compiling this directly; it publishes the app first
; and passes the version from NightTech.Shield.csproj.

#define AppName "Night Tech Shield"
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define Publisher "Night Tech Solutions"
#define PublisherUrl "https://nighttech.solutions/"
#define HelpUrl "https://nighttech.solutions/security-apps/#shield"
#define ExeName "NightTechShield.exe"

[Setup]
; Never change AppId after the first public release: Windows uses it to match upgrades.
AppId={{4F0B8E2C-7D1A-4C55-9B3E-2A6D8C5E1F47}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#Publisher}
AppPublisherURL={#PublisherUrl}
AppSupportURL={#HelpUrl}
AppUpdatesURL={#HelpUrl}
AppCopyright=© 2026 {#Publisher}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#Publisher}
VersionInfoDescription={#AppName} installer

; Shield runs as administrator, so it installs for everyone in Program Files.
PrivilegesRequired=admin
DefaultDirName={autopf}\Night Tech Shield
DisableProgramGroupPage=yes
DisableDirPage=auto

; Windows 10 version 2004 or newer, 64-bit
MinVersion=10.0.19041
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Asks people to close Shield before upgrading or uninstalling (matches App.MutexName)
AppMutex=Global\NightTechSolutions.Shield
CloseApplications=yes

LicenseFile=..\LICENSE.txt
SetupIconFile=..\src\NightTech.Shield\Assets\shield.ico
UninstallDisplayIcon={app}\{#ExeName}
UninstallDisplayName={#AppName}
WizardStyle=modern
WizardImageFile=branding\wizard-100.bmp,branding\wizard-200.bmp
WizardSmallImageFile=branding\small-100.bmp,branding\small-200.bmp

OutputDir=..\dist
OutputBaseFilename=NightTechShield-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes

#ifdef Sign
SignTool=ntsign
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This installs [name/ver] on your computer.%n%nShield checks your PC with Microsoft Defender, which is built into Windows, and adds Night Tech's own checks for adware, browser hijacks and sneaky startup programs. It's free, with no ads, accounts or tracking.%n%nClose other apps before you continue.
FinishedLabel=Night Tech Shield is installed. Open it and choose Scan now. Nothing is changed until you choose what to fix.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Dirs]
; Made by the (administrator) installer, so an ordinary account can't make it first. Shield locks it down further on first run.
Name: "{commonappdata}\Night Tech Solutions"; Permissions: admins-full system-full
Name: "{commonappdata}\Night Tech Solutions\Shield"; Permissions: admins-full system-full

[Files]
Source: "..\publish\{#ExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#ExeName}"; Comment: "Check this PC for malware and adware"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#ExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#ExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent shellexec

[Code]
// Shield's folder holds the undo log and the startup items and hosts-file copies it kept.
// Uninstalling asks before deleting it, so nothing that could be put back is lost by surprise.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\Night Tech Solutions\Shield');
    if DirExists(DataDir) and not UninstallSilent then
    begin
      if MsgBox('Also delete Shield''s record of changes and the copies it kept?' + #13#10 + #13#10 +
                'Choose No to keep them, so changes can still be put back if you reinstall Shield.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;
