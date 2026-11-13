; Inno Setup script for RV Timeline (built by .github/workflows/release.yml).
; Per-user install: no administrator rights needed on the examiner's PC.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\.."
#endif

[Setup]
AppId={{BE690C03-DA5F-42F0-9284-A86D5FF89D0E}
AppName=RV Timeline
AppVersion={#AppVersion}
AppPublisher=Rakvor
AppPublisherURL=https://github.com/Panacota96/rv-timeline
DefaultDirName={localappdata}\Programs\Rakvor\RV Timeline
DefaultGroupName=Rakvor
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile={#SourceDir}\LICENSE
OutputBaseFilename=rv-timeline-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#SourceDir}\assets\brand\rv.ico
ChangesEnvironment=yes
UninstallDisplayIcon={app}\rv-timeline-gui.exe

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "addtopath"; Description: "Add the rv-timeline command to PATH"; Flags: checkedonce
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\target\release\rv-timeline.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\target\release\rv-timeline-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}"
Source: "{#SourceDir}\NOTICE"; DestDir: "{app}"
Source: "{#SourceDir}\CHANGELOG.md"; DestDir: "{app}"
Source: "{#SourceDir}\docs\*"; DestDir: "{app}\docs"; Flags: recursesubdirs
; The sample case folder (six tool runs, case log, registry) that "build --case-dir" reads, with its README.
Source: "{#SourceDir}\examples\sample\case\*"; DestDir: "{app}\examples\sample\case"; Flags: recursesubdirs createallsubdirs
Source: "{#SourceDir}\examples\sample\README.md"; DestDir: "{app}\examples\sample"

[Icons]
Name: "{group}\RV Timeline"; Filename: "{app}\rv-timeline-gui.exe"
Name: "{group}\RV Timeline documentation"; Filename: "{app}\docs"
Name: "{autodesktop}\RV Timeline"; Filename: "{app}\rv-timeline-gui.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\rv-timeline-gui.exe"; Description: "Start RV Timeline"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Dir: string): Boolean;
var
  Paths: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Paths) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;
