# (Draft) Creating a relatively simple WDAC Policy

These are just my notes after overhauling the WDAC Policy I currently use. Very much a WIP and might well have mistakes in it.

My scenario is similar to that outlined in https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-policy-for-fully-managed-devices

The Wizard offers three base templates, with varying levels of trust:

1. Default Windows Mode
   - Windows OS Components
   - Microsoft Store Applications
   - Office 365, OneDrive, Teams
   - WHQL Signed Kernel Drivers
2. Allow Microsoft Mode
   - Windows OS Components
   - Microsoft Store Applications
   - Office 365, OneDrive, Teams
   - WHQL Signed Kernel Drivers
   - All Microsoft signed applications (that is, apps such as PowerToys or sysinternals that are not included with Windows but are still from Microsoft)
3. Signed And Reputable Mode
   - Windows OS Components
   - Microsoft Store Applications
   - Office 365, OneDrive, Teams
   - WHQL Signed Kernel Drivers
   - All Microsoft signed applications
   - Files with good reputation using ISG (Intelligent Security Graph, basically what is used in SAC to determine if an app is trustworthy without having it explicitly deny/allowlisted)

There is a tradeoff between trust and usability. I would reccommend using the 3rd base template, as it offers the most usability (and the benefits of SAC) while allowing you to allowlist falsely blocked files.

I personally selected the Default Windows Mode base template.

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

If you are on a system you are unsure will function properly with WDAC, enable the Boot Audit on Failure option.

On the next screen, you can add custom rules yourself. I recommend blocking cmd.exe (can be found in `C:\Windows\System32` as well as `C:\Windows\SysWow64` by hash as .bat/.cmd scripts are not restricted like powershell scripts. (executables a .bat/.cmd script attempts to call will still be restricted however). The next button will then generate the policy as well as the binary (which should be a `.cip` file). In my experience if converting a policy outputs a `SiPolicy.p7b` file, something has gone wrong.

Don't apply it just yet, as you also need to generate policies for your third party applications. In my case, these were the programs that weren't already trusted by the base policy:

- Firefox
- Powertoys
- Tor Browser

While it is possible to use the wizard and manually add rules from the event log, this is a pain in my experience. It is also relatively easy to create filepath rules, but this is a potential risk should an attacker be able to drop a malicious executable into an allowlisted directory. I have had good results finding the directory where the program is installed - right click and check the properties of the start menu shortcut to see where the executable is - opening it up in an elevated Powershell, and running 

```
New-CIPolicy -Level FilePublisher -Fallback Hash -UserPEs -ScanPath .\ -FilePath C:\Users\Username\Documents\app.xml
```
This will generate a new supplemental policy that you can merge with your base policy. If you get the error `An item with the same key has already been added.
`, simply run the command again.

https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create
https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy?view=windowsserver2022-ps

- FilePublisher trusts specific files from the specified publisher, with a version at or above the specified version number.
- Since companies are not the best about consistently signing files, fallback to hash rules (these will be invalidated after an update, regenerate your rules afterwards). Depending on the app, you may not need to do this. Firefox for example doesn't appear to need a lot of hash rules and upgrading in place does not require a new policy in my experience.
- ScanPath is the directory to be scanned.
- UserPEs means that the generated policy is for userspace executables, not drivers.
- Filepath determines where the generated policy will be placed.

Open up the generated xml in notepad and remove the audit mode rule.

Once you have done this for all the programs you wish to allowlist, you can then merge them all in the WDAC wizard. In my case I had to manually edit the merged policy and reenable the HVCI option for some reason.

You can apply the policy by opening an elevated powershell, navigating to the directory where it's stored, and running `CiTool.exe --update-policy ".\{GUID}.cip"` (tab autocomplete is very helpful for this).

To deactivate a policy (such as when running `winget upgrade --all`)  run `CiTool.exe --remove-policy "{GUID}"` in an elevated Powershell. You can then reboot to enforce changes.

If you want to temporarily turn a policy off without rebooting, use the Wizard to place it in audit mode and run `CiTool.exe --update-policy ".\{GUID}.cip"` again.


