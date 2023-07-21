# Configuring Windows 11 Pro/Enterprise 

(Read the whole guide before going through with it please!)

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

It is up to you whether or not to use it. Also note that it's possible to craft a more restrictive allowlist policy than what Smart App Control has using WDAC, but this is more for advanced users.


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
6. (Optional) Widgets and Live Tiles 

# OS Diagnostics / Windows Spotlight (Sends back hardware data, among other things)

If you are on Pro, you cannot fully disable OS diagnostics. Opt out of optional diagnostics on first setup and do not attempt to download third party tools that claim to disable telemetry. Since you're sending hardware data anyways, it is most likely pointless to disable Spotlight on Pro edition.

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

Note: given Microsoft's push for Windows Copilot I suspect Cortana will be sunsetted within the next several months or so, along with these group policies. Hopefully there will be a simple, generalized group policy to disable it when Copilot becomes widely available.

# Defender / Smartscreen

Go to **Windows Security > Virus and Threat Protection > Manage Settings > Automatic Sample Submission.**
Click to disable it.

If you have chosen to not use Smart App Control, go to **Windows Security > App and Browser Control > Check Apps and Files** and disable it.

It is probably the best to also disable **Smartscreen for Microsoft Edge**, as it has been shown to leak full URLs and browsing history to Microsoft. 

# Edge Optional Features

By default, Edge has many features that could leak private data and browsing history:

In `edge://settings/privacy` disable the following: 
- [ ] Search and service improvement > Help improve Microsoft products by sending the results from searches on the web
- [ ] Personalization & advertising > Allow Microsoft to save your browsing activity including history, usage, favorites, web content, and other browsing data to personalize Microsoft Edge and Microsoft services like ads, search, shopping and news.
- [ ] Security > Microsoft Defender SmartScreen
- [ ] Security > Website typo protection
- [ ] Security > Turn on site safety services to get more info about the sites you visit
- [ ] Services > Use a web service to help resolve navigation errors
- [ ] Services > Suggest similar sites when a website can't be found
- [ ] Services > Save time and money with Shopping in Microsoft Edge
- [ ] Services > Get notified when creators you follow post new content
- [ ] Services > Show opportunities to support causes and nonprofits you care about
- [ ] Services > Get notifications of related things you can explore with Discover
- [ ] Services > Let Microsoft Edge help keep your tabs organized

(Basically, turn off everything under the Services section.)

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


# Widgets / Live Tiles 

These make potentially unneeded connections back to Microsoft, but from what I've seen they do not appear to send sensitive user data back. However, if you wish to disable them:

**Computer Configuration > 	Windows Components > Widgets > AllowWidgets** should be set to **Disabled**.

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

# App Management

Rather than using a search engine to look for and download app - which is prone to being gamed by [malicious sites](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-to-spread-malware-in-legit-software/), it is preferable to use the `winget` package manager which comes preinstalled on Windows 11 by default. To look for a package, open up a terminal window and type in `winget search "Package Name"`. You can then verify the publisher (which is handy for Microsoft Store apps) by copying the application ID and running `winget show "application ID"`. 

According to [this](https://github.com/microsoft/winget-cli/discussions/2534) winget packages do go through some amount of review before being added in:

> I don't see where security risks would be an issue here because every installer goes through Dynamic Analysis (Virus Scan) in the Pipelines' VMs, and if there's a PUA or malware in the installer, it's immediately flagged by the pipelines. The PR is also manually validated by Moderators, in either VMs, or Bare Metal - so installers are always double checked to make sure that it isn't a malicious package intended to steal people's passwords or monitor what they're typing on their keyboard.
Even if the pipelines cannot catch the malware issue, depending on the antivirus software someone has, all installers from WinGet are downloaded to %TEMP%\WinGet, except for .appx(bundle) and .msix(bundle), where your antivirus software will probably scan it before it's executed to install it onto your PC.

While this is by no means a guarantee, this should reduce the chances of getting served outright malware.

Occasionally an app will show up as being downloadable from either the Store or the publisher website. Currently there does not seem to be any major security difference between the two, so it is up to the user to decide which to install.  



# MDAG / Windows Sandbox






# BlackLotus Revocations

https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d

1. Make sure your Windows install is fully up to date (has the July 11 2023 updates installed)
2. Enter the following into an elevated command prompt: `reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x30 /f`
3. Restart.
4. Wait five minutes.
5. Restart again.

Event IDs 1035 and 276 should be logged under the Windows Event Viewer.
