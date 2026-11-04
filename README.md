# Night Tech Shield

A free malware and adware check for Windows 10 and 11, from [Night Tech Solutions](https://nighttech.solutions).

Shield uses **Microsoft Defender**, which is built into Windows, to scan and remove malware. It adds Night Tech's own
checks for the problems antivirus programs often leave alone: adware, fake PC optimizers, hijacked browsers, sneaky startup
programs, a tampered hosts file, an unexpected web proxy, and remote-control programs a scammer may have installed.

Scanning only looks. Nothing changes until you choose what to fix, and Shield asks first.

**Download:** [NightTechShield-Setup.exe](https://github.com/Zetes-78/NightTech-Shield/releases/latest/download/NightTechShield-Setup.exe)
· [How to use it](https://nighttech.solutions/shield/)

## What it checks

| Area | What Shield looks at | What the fix does |
| --- | --- | --- |
| Antivirus | Defender is on, real-time protection, definitions age, last scan, Tamper Protection, other antivirus programs | Turns real-time protection on, updates definitions, runs a quick scan, or opens Windows Security |
| Threats | What Defender has found and whether it was removed | Asks Defender to remove it |
| Startup | Run keys, Startup folders: hidden PowerShell, scripts from AppData, unsigned programs from temp folders, missing programs | Stops it starting (kept, so it can be put back) |
| Programs | Adware, scareware "optimizers", driver updaters, activation cracks, remote-control programs | Runs the program's own uninstaller |
| Browsers | Chrome, Edge, Brave, Vivaldi, Firefox: search engine, start pages, extensions not from the store, forced policies | Shows the browser's own reset steps; removes forced policies |
| Network | Hosts file entries that redirect or block well-known sites; web proxy | Turns those hosts lines into comments; turns the proxy off |

More menu: Defender quick scan, full scan, scan a folder, update definitions, Microsoft Defender Offline scan, undo
changes, save a report.

## Safety

- Every startup item, policy, hosts-file and proxy change is written to an undo log first, and can be put back with
  **More > Undo changes**. Files are moved into Shield's folder, never deleted.
- Shield can make a Windows restore point before fixing (on by default).
- Remote-control programs and anything a person might use on purpose are shown but not ticked.
- Shield's folder (`%ProgramData%\Night Tech Solutions\Shield`) is for administrators only, so other accounts can't
  change what Undo writes.
- Browsers are never started with administrator rights: Shield shows the browser's own reset page to open instead.
- Nothing about the PC is sent anywhere. No accounts, ads or tracking.

Shield reports what it sees when it scans. It can't promise a PC is free of every kind of malware.

## Build

Needs the .NET 8 SDK and Inno Setup 6.3+.

```powershell
.\build.ps1            # tests, publish, installer in dist\
dotnet run --project tests\NightTech.Shield.CoreTests   # just the tests
```

`src/NightTech.Shield.Core` holds the rules and has no Windows calls, so the tests run anywhere.
`src/NightTech.Shield` is the Windows app (WPF): `Windows/Collector.cs` reads, `Windows/Fixer.cs` changes and undoes.

## License

MIT. Microsoft Defender and Windows are trademarks of Microsoft; Night Tech Solutions isn't affiliated with Microsoft.

---

Need a hand? Call Night Tech Solutions at (864) 381-8510, text (864) 497-2701, or visit
[nighttech.solutions](https://nighttech.solutions).
