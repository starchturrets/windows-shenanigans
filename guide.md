# Configuring Windows 11 Pro/Enterprise 

(Read the whole guide before going through with it please!)
Disclaimer: I am not a security researcher, I simply read documentation, played around a bit with VMs, and talked to people in various privsec matrix channels. This is by no means comprehensive and/or a guarantee of privacy and security on Windows, as it is very much still a Work in Progress.

# Things to note before installing: 
 
- [ ] Does your device officially support Windows 11? Can Secure Boot and TPM be enabled in the firmware settings? CSM legacy boot mode should also be disabled. If not, do not attempt to bypass the hardware requirements, which provide much of the benefits of Windows 11 by allowing certain security features to be toggled on by default. If you're on an unsupported device and cannot upgrade, consider ChromeOS Flex or a Linux distro. 
- [ ] If you're not planning on dualbooting or running Linux, and your device gives you the option to, disable the Microsoft UEFI CA in the secure boot settings. This will improve boot security because instead of trusting hundreds of bootloaders you will only be trusting Windows (and your OEM) certificates.
- [ ] Does your OEM/Motherboard manufacturer provide you with bloatware delivered through the WPBT? There may be an option in the firmware to disable it.

# On Install:

It is best not to login to a Microsoft Account on Windows. (Note: add explanations why!) On Windows 11 Pro it is possible to skip the requirement to login by clicking on the “Set up for work or school” option -> Sign-in Options -> Domain Join.

Screenshots will be posted here when I get to do more thorough testing in VMs.

Enterprise also makes it easy to click past the login screen.

Opt out of all optional diagnostics / Inking and Typing / Location / Etc. 

# Smart App Control 

Smart App Control is a tradeoff between privacy and security. On the one hand, it improves security by mitigating unsigned code from running while using reputation checks to make sure legitimate files are not blocked, on the other hand it needs to send file metadata to Microsoft in order to function. As the Microsoft Privacy Policy puts it: 

> Where supported, Smart App Control helps check software that is installed and runs on your device to determine if it is malicious, potentially unwanted, or poses other threats to you and your device. **On a supported device, Smart App Control starts in evaluation mode and the data we collect for Microsoft Defender SmartScreen such as file name, a hash of the file’s contents, the download location, and the file’s digital certificates, is used to help determine whether your device is a good candidate to use Smart App Control for additional security protection.** 

> ...

> When either Microsoft Defender SmartScreen or Smart App Control checks a file, data about that file is sent to Microsoft, including the file name, a hash of the file’s contents, the download location, and the file’s digital certificates.

It is ultimately up to you whether or not to use it. I personally don't due to how inflexible its rules currently are - there's no way to whitelist an application/executable should it get blocked short of disabling Smart App Control entirely - and once disabled, it cannot be reenabled without reinstalling Windows.

Also note that it's possible to craft a more restrictive allowlist policy than what Smart App Control has using AppLocker and/or WDAC (Smart App Control basically uses WDAC under the hood), but this is more for advanced users, and while I have a basic WDAC policy setup for myself, I still don't fully understand hardening it against bypasses.


# Things that phone home to Microsoft

This section is based off of limited testing in a VM, along with documentation from Microsoft:

https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services

https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints

Based off what I've seen, these are the more relevant items:

1. OS Diagnostics
2. Windows Spotlight
3. Bing Start Menu (Cortana and Search) 
4. Edge Optional Features
5. Certain aspects of Windows Defender (Smartscreen, Automatic Sample Submission)
6. (Optional) Widgets and Live Tiles, Windows Media Player 

# OS Diagnostics / Windows Spotlight (Sends back hardware data, among other things)

If you are on Pro, you cannot fully disable OS diagnostics. Opt out of optional diagnostics on first setup and do not attempt to download third party tools that claim to disable telemetry. Since you're sending hardware data anyways, it is most likely pointless to disable Spotlight on Pro edition.

Note: it's likely possible to block `diagtrack.dll` with WDAC but I'll have to test that. 

<details>

<summary>If you are on Enterprise </summary>

If on Enterprise, open the group policy editor and go to **Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds.** 

Double-click **Allow Telemetry (or Allow diagnostic data on Windows 11 and Windows Server 2022).**

Select the "Send no Diagnostic Data" Option, then click OK to apply changes.


## Windows Spotlight

Windows Spotlight sends back similar hardware data to required diagnostics. To turn it off:

- [ ] Enable the following Group Policy User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off all Windows spotlight features.

- [ ] Enable the following Group Policy Computer Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off cloud optimized content.

According to Microsoft docs, this must be done within **15 minutes of first install.**

</details>


# Bing Start Menu

By default, the start menu search searches the web, which could leak your local file queries to Microsoft. According to documentation, the following is needed to disable Cortana and Search:

Find the Cortana Group Policy objects under **Computer Configuration > Administrative Templates > Windows Components > Search.**

- [ ] Allow Cortana should be **Disabled**
- [ ] Allow search and Cortana to use location should be **Disabled**
- [ ] Do not allow web search should be **Enabled**
- [ ] Don't search the web or display web results in Search should be **Enabled**

In addition, I've found that you also need to set **User Configuration > Administrative Templates > Windows Components > File Explorer > Turn off display of recent search entries in the File Explorer search box** to **Enabled.**

Note: look into seeing if just `winget uninstall Cortana` + the single group policy above will be enough to deal with Cortana + Search.

~~Note: given Microsoft's push for Windows Copilot I suspect Cortana will be sunsetted within the next several months or so, along with these group policies. Hopefully there will be a simple, generalized group policy to disable it when Copilot becomes widely available.~~

According to elevenforums, this will be the group policy to enable in order to kill copilot when it rolls out: Computer Configuration > Administrative Templates > Start Menu and Taskbar​ > Hide the Copilot button


# Defender / Smartscreen

Go to **Windows Security > Virus and Threat Protection > Manage Settings > Automatic Sample Submission.**
Click to disable it.

If you have chosen to not use Smart App Control, go to **Windows Security > App and Browser Control > Check Apps and Files** and disable it.

It is probably the best to also disable **Smartscreen for Microsoft Edge**, as it has been shown to leak full URLs and browsing history to Microsoft. 

# Edge Optional Features

Using Edge is a trade off between privacy and security. By default, Edge has many features that can and have leaked private data and browsing history to Microsoft. On the other hand, it does have legitimate security features such as MDAG and Enhanced Security Mode. It is up to you whether to use it or to just use another Browser such as Brave/Chrome/Firefox.

In `edge://settings/privacy` disable the following: 
- [ ] Search and service improvement > Help improve Microsoft products by sending the results from searches on the web
- [ ] Personalization & advertising > Allow Microsoft to save your browsing activity including history, usage, favorites, web content, and other browsing data to personalize Microsoft Edge and Microsoft services like ads, search, shopping and news.
- [ ] Security > Microsoft Defender SmartScreen
- [ ] Security > Website typo protection
- [ ] Security > Turn on site safety services to get more info about the sites you visit

Note: it may seem counterproductive to disable security features, however Microsoft states in their Edge privacy whitepaper that:

> SmartScreen performs a synchronous reputation check of the URL. SmartScreen checks on all URLs that aren't categorized as top traffic. **Microsoft Edge passes the URL, relevant information about the site, an identifier unique to your device, and general location information to the SmartScreen service to determine the safety of the site.** 

https://learn.microsoft.com/en-us/microsoft-edge/privacy-whitepaper/#smartscreen

This is an extremely silly way to do it imo when Google safe browsing has shown it's possible to implement it in a safe way without blasting all the URLs you visit away to Microsoft.
<details>
 <summary>Turn off everything under the Services section.</summary>

- [ ] Services > Use a web service to help resolve navigation errors (note: this only seems to be used for captive portals and isn't so harmful?)
- [ ] Services > Suggest similar sites when a website can't be found
- [ ] Services > Save time and money with Shopping in Microsoft Edge
- [ ] Show suggestions to follow creators in Microsoft Edge
- [ ] Services > Get notified when creators you follow post new content
- [ ] Services > Show opportunities to support causes and nonprofits you care about
- [ ] Services > Get notifications of related things you can explore with Discover
- [ ] Services > Let Microsoft Edge help keep your tabs organized

</details>
Using the Bing sidebar is not very privacy friendly (especially since it can be granted privileged access to your web browsing activity), so it is best to disable it.

Under `edge://settings/sidebar`, disable the following:
- [ ] App and notification settings > Discover > Show Discover
- [ ] App and notification settings > Discover > Automatically open Bing Chat in the sidebar
- [ ] Page Context
- [ ] Automatically show shopping suggestions and prompts



In `edge://settings/languages` disable the following: 
- [ ] Offer to translate pages that aren't in a language I read
- [ ] Use text prediction
- [ ] Enable grammar and spellcheck assistance


# Widgets / Live Tiles, Windows Media Player 

These make potentially unneeded connections back to Microsoft, but from what I've seen they do not appear to send sensitive user data back. However, if you wish to disable them:

**Computer Configuration > 	Windows Components > Widgets > AllowWidgets** should be set to **Disabled**.

Alternatively, Widgets can be completely uninstalled by doing `winget uninstall "Windows Web Experience Pack"` in an elevated PowerShell window. 

The Windows Media Player uses Bing by default to auto fetch Music metadata. This can be disabled by opening the app, going to settings, and toggling off "Search for missing Album and Artist art online".

# Debloating

There are several things to put up with on Windows:

- Manufacturer bloatware, such as preinstalled third party ~~malware~~ antiviruses
- Start Menu shortcuts which are pinned by default
- Preinstalled third party apps such as Spotify
- Microsoft apps that you don't like

Manufacturer bloatware usually isn't too much of a problem if you're doing a clean install, though OEMs can and have abused WPBT as well as driver updates to get around this.

Start menu shortcuts and preinstalled third party apps can be easily removed by right clicking and unpinning / uninstalling them.

Microsoft Apps such as Cortana can be removed using the `winget` package manager.

1. Open an elevated powershell window and type in `winget list`
2. Copy the name of the package you wish to uninstall and type in `winget uninstall PACKAGE_NAME`

Note that uninstalling Cortana does not remove the need to apply the above group policies regarding Cortana and Search. You also cannot uninstall Microsoft Edge.  Do not go overboard uninstalling system apps in case you break something, and *please*, do not download third party debloater tools.

# Security Stuff

- [ ] Make Sure everything is up to date! 
- [ ] Keep Camera / Mic / Location off when not in use
- [ ] Set UAC to the max, and consider using a non admin user
- [ ] Use `winget` to manage apps
- [ ] Make sure whatever exploit mitigations that are supported by the hardware are on, see Controlled Folder Access as well
- [ ] (Relatively Easy) Use AppLocker to deny executables from running in the Downloads folder
- [ ] (Somewhat Advanced) Use a WDAC policy to mimic Smart App Control's functionality while adding a bit more flexibility
- [ ] (Advanced) Run WDAC without the Intelligent Security Graph
- [ ] Use VMs to run untrusted executables (Hyper V / MDAG / Windows Sandbox)
- [ ] Use attack surface reduction rules to harden Office, disable VBA macros.
- [ ] Configure Bitlocker
- [ ] Apply the BlackLotus secure boot revocations
- [ ] Use admx group policies to improve Edge security
  
# Keep Everything Updated

Check your Windows Update settings page regularly, especially on the second Tuesday of each month, as Microsoft usually releases security updates then ("Patch Tuesday").

Windows can also automatically update certain Microsoft products such as Office through windows update.

Also check "Optional Updates" for driver and firmware updates. However, in some cases the drivers provided by Windows Update are old, and it is better to use the OEM tool to update drivers. This goes for AMD devices.  

Winget can update some apps, but not those from the Microsoft Store, so you'll have to check things there separately.

# Camera / Mic / Location

Due to currently terrible permission control, not all apps can be denied the camera or mic permission. So keep the global toggle disabled when not in use, which should turn it off for legacy desktop apps as well. Note that apps with admin access can override this setting.

# User Account Control

Set UAC to the highest level, this will mitigate some bypasses. Even better, you can create and use a non admin user account to daily drive with, and only elevate into the admin account when absolutely needed.

# App Management

Rather than using a search engine to look for and download app - which is prone to being gamed by [malicious sites](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-to-spread-malware-in-legit-software/), it is preferable to use the `winget` package manager which comes preinstalled on Windows 11 by default. To look for a package, open up a terminal window and type in `winget search "Package Name"`. You can then verify the publisher (which is handy for Microsoft Store apps) by copying the application ID and running `winget show "application ID"`. 

According to [this](https://github.com/microsoft/winget-cli/discussions/2534) winget packages (community packages, the Store is larger and lets shady stuff slip through) do go through some amount of manual review before being added in:

> I don't see where security risks would be an issue here because every installer goes through Dynamic Analysis (Virus Scan) in the Pipelines' VMs, and if there's a PUA or malware in the installer, it's immediately flagged by the pipelines. The PR is also manually validated by Moderators, in either VMs, or Bare Metal - so installers are always double checked to make sure that it isn't a malicious package intended to steal people's passwords or monitor what they're typing on their keyboard.
Even if the pipelines cannot catch the malware issue, depending on the antivirus software someone has, all installers from WinGet are downloaded to %TEMP%\WinGet, except for .appx(bundle) and .msix(bundle), where your antivirus software will probably scan it before it's executed to install it onto your PC.

While this is by no means a guarantee, this should reduce the chances of getting served outright malware.

Occasionally an app will show up as being downloadable from either the Store or the publisher website. Currently there does not seem to be any major security difference between the two (aside from making WDAC Configuration somewhat harder), so it is up to the user to decide which to install.  

Microsoft Store apps can be sandboxed (as UWP), however this is not enforced. Check the permissions page and make sure that an app does not have the "Use All System Resources" permission if you wish for it to be sandboxed.

# Application Control

Note: this is based off of my limited testing on my own device, as well as Microsoft Documentation

https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/

Windows offers several methods to stop untrusted executables from running, such as AppLocker or Smart App Control / WDAC. Each of them have their own advantages and disadvantages, but they do help mitigate attacks such as those from clicking on disguised executables.  

I have not tested AppLocker yet, so I will only talk about Smart App Control / WDAC.

WDAC (Windows Defender Application Control) is what runs under the hood of Smart App Control, however SAC exposes far less configuration. SAC can be enabled on new installs by opening the Windows Security App and going to **App and Browser Control > Settings for Smart App Control** and selecting the Activated option.

While this means it is dead simple, it is also a blunt all or nothing - if a dll critical to signal desktop or another similar app is blocked, there is no option to allowlist it, only turn it off entirely, and it cannot be reenabled without reinstalling the OS. So unless you restrict your usage to a few basic apps it is unlikely it will work well with you. 

Another option is to create and apply a WDAC policy manually. Microsoft offers the [WDAC wizard](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard) to simplify things, but it unfortunately still has a steep learning curve.

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

There is a tradeoff between trust and usability. I would reccommend using the 3rd base template, as it offers the most usability (and the benefits of SAC) while allowing you to allowlist falsely blocked files. Currently, I run a variant of the second base template with chrome, firefox, and powertoys allowed.


# Microsoft Office

Unfortunately, unless you're on an Enterprise 365 Office subscription (unlikely) you will not be able to make use of MDAG like on Edge. That being said, there are still a few steps you can take to improve security on Office.

https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide

ASR rules can be deployed without a subscription and in some cases have mitigated the exploit of a CVE: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884

They can be found under: **Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction Rules.**

| ASR Rule                                                                                          | GUID                                   |
|---------------------------------------------------------------------------------------------------|----------------------------------------|
| Block abuse of exploited vulnerable signed drivers                                                | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| Block Adobe Reader from creating child processes                                                  | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` |
| Block all Office applications from creating child processes                                       | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block credential stealing from the Windows local security authority subsystem (lsass.exe)         | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block executable content from email client and webmail                                            | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` |
| Block executable files from running unless they meet a prevalence, age, or trusted list criterion | `01443614-cd74-433a-b99e-2ecdc07bfc25` |
| Block execution of potentially obfuscated scripts                                                 | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` |
| Block JavaScript or VBScript from launching downloaded executable content                         | `d3e037e1-3eb8-44c8-a917-57927947596d` |
| Block Office applications from creating executable content                                        | `3b576869-a4ec-4529-8536-b80a7769e899` |
| Block Office applications from injecting code into other processes                                | `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` |
| Block Office communication application from creating child processes                              | `26190899-1602-49e8-8b27-eb1d0a1ce869` |
| Block persistence through WMI event subscription                                                  | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |
| Block process creations originating from PSExec and WMI commands                                  | `d1e49aac-8f56-4280-b9ba-993a6d77406c` |
| Block untrusted and unsigned processes that run from USB                                          | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` |
| Block Win32 API calls from Office macros                                                          | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` |
| Use advanced protection against ransomware                                                        | `c1db55ab-c21a-4637-bb3f-a12568109d35` |

Activate it, and click the display status button. Then paste in the GUIDs of the ASR rules you wish to activate in the left column and 1 in the right column to activate them. You can get the GUIDs from here: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference. It is possible that it could interfere with your workflow but I personally haven't noted any issue with just turning all of them on.


- Disable VBA Macros.
- Use Attack Surface Reduction rules


# MDAG / Windows Sandbox for untrusted URLs / executables






# BlackLotus Revocations

https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d

1. Make sure your Windows install is fully up to date (has the July 11 2023 updates installed)
2. Enter the following into an elevated command prompt: `reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x30 /f`
3. Restart.
4. Wait five minutes.
5. Restart again.

Event IDs 1035 and 276 should be logged under the Windows Event Viewer.
