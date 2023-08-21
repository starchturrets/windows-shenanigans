# (Draft) Creating a relatively simple WDAC Policy

These are just my notes after overhauling the WDAC Policy I currently use. Very much a WIP and might well have mistakes in it.

Base template selected: Default Windows Mode, which trusts: 
- Windows OS Components
- Microsoft Store Applications
- Office 365, OneDrive, Teams
- WHQL Signed Kernel Drivers

This isn't perfect (Microsoft signed binaries can and have been abused to circumvent WDAC policies, as well as vulnerable drivers), but it's a good start. From testing on my own system (HP Pavilion Aero 13, Intel) nothing major seems to break with this template, but issues have been reported on AMD systems due to their wonky driver signing (note: add source!). I am also not sure how well this works with custom built PCs. Have your Bitlocker recovery key handy just in case.

Install the WDAC Wizard from Microsoft: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard#downloading-the-application

It's probably a good idea to tick on these two options in the application settings:

- [ ] Create policies With Microsoft's Recommended Block Rules 
- [ ] Create policies With Microsoft's Recommended Driver Block Rules

These should somewhat limit abusable Microsoft executables / vulnerable drivers, although there have been major issues with this in the past (Note: link article about Microsoft not updating the HVCI list for two years for some reason). A purely allowlist driver policy would be even better than playing whack a mole with denylisting, but I haven't done this myself yet. 

Note: WSL is unfortunately blocked by WDAC as it is a possible bypass method. 

Create a base policy in the multiple template format and select the directory to which it should be saved.

After clicking next, toggle the following options:

- Enforce Store Applications 
- Hypervisor Protected Code Integrity 
- Require WHQL
- Disable Flight Signing
- Require EV Signers
- Audit mode off

On the next screen, you can add custom rules yourself. I recommend blocking cmd.exe by hash (as well as turning it off in GPO) as .bat/.cmd scripts are not restricted like powershell scripts. (executables a .bat/.cmd script attempts to call will still be restricted however). The next button will then generate the policy as well as the binary (which should be a `.cip` file).

Don't apply it just yet, as you also need to generate policies for your third party applications. In my case, these were the programs that weren't already trusted by the base policy:

- Firefox
- Powertoys
- Tor Browser

While it is possible to use the wizard and manually add rules from the event log, this is a pain in my experience. It is also relatively easy to create filepath rules, but this is a potential risk should an attacker be able to drop a malicious executable into an allowlisted directory. I have had good results finding the directory where the program is installed - right click and check the properties of the start menu shortcut to see where the executable is - opening it up in an elevated Powershell, and running 

´New-CIPolicy -Level FilePublisher -Fallback Hash -UserPEs -ScanPath .\ -FilePath C:\Users\Username\Documents\app.xml´

This will generate a new supplemental policy that you can merge with your base policy. 

https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create
https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy?view=windowsserver2022-ps

- FilePublisher trusts specific files from the specified publisher, with a version at or above the specified version number.
- Since companies are not the best about consistently signing files, fallback to hash rules (these will be invalidated after an update).
- ScanPath is the directory to be scanned.
- UserPEs means that the generated policy is for userspace executables, not drivers.
- Filepath determines where the generated policy will be placed.

Open up the generated xml in notepad and remove the audit mode rule.

Once you have done this for all the programs you wish to allowlist, you can then merge them all in the WDAC wizard. In my case I had to manually edit the merged policy and reenable the HVCI option for some reason.

You can apply the policy by opening an elevated powershell, navigating to the directory where it's stored, and running `CiTool.exe --update-policy ".\{GUID}.cip"` (tab autocomplete is very helpful for this).

You can then reboot to enforce changes.

To deactivate a policy (such as when running `winget upgrade --all`)  run `CiTool.exe --remove-policy "{GUID}"` in an elevated Powershell.
