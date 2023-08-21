# (Draft) Creating a relatively simple WDAC Policy

These are just my notes after overhauling the WDAC Policy I currently use.

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

These should somewhat limit abusable Microsoft executables / vulnerable drivers, although there have been issues in the past (Note: link article about Microsoft not updating the HVCI list for two years for some reason).  

Note: WSL is unfortunately blocked by WDAC as it is a possible bypass method. 
