# (Draft) Creating a relatively simple WDAC Policy

These are just my notes after overhauling the WDAC Policy I currently use.

Base template selected: Default Windows Mode, which trusts: 
- Windows OS Components
- Microsoft Store Applications
- Office 365, OneDrive, Teams
- WHQL Signed Kernel Drivers

This isn't perfect (Microsoft signed binaries can and have been abused to circumvent WDAC policies, as well as vulnerable drivers), but it's a good start. 

Install the WDAC Wizard from Microsoft: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard#downloading-the-application

