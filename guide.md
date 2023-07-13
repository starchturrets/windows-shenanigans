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
6. Widgets and Live Tiles 

# OS Diagnostics

If you are on Pro, you cannot fully disable OS diagnostics. Opt out of optional diagnostics on first setup and do not attempt to download third party tools that claim to disable telemetry. 

If on Enterprise, open the group policy editor and go to **Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds.** 

Double-click **Allow Telemetry (or Allow diagnostic data on Windows 11 and Windows Server 2022).**

Select the "Send no Diagnostic Data" Option, then click OK to apply changes.


# Windows Spotlight

Windows Spotlight sends back similar hardware data to required diagnostics. As required diagnostics are sent anyways on Pro, this is not so much of a concern.

If on Enterprise:

- [ ] Enable the following Group Policy User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off all Windows spotlight features.

- [ ] Enable the following Group Policy Computer Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off cloud optimized content.

According to Microsoft docs, this must be done within **15 minutes of first install.**

# Bing Start Menu

By default, the start menu search searches the web, which could leak your local file queries to Microsoft. According to documentation, the following is needed to disable Cortana and Search:

Find the Cortana Group Policy objects under **Computer Configuration > Administrative Templates > Windows Components > Search.**

- [ ] Allow Cortana should be **Disabled**
- [ ] Allow search and Cortana to use location should be **Disabled**
- [ ] Do not allow web search should be **Enabled**
- [ ] Don't search the web or display web results in Search should be **Enabled**

In addition, I've found that you also need to set **User Configuration > Administrative Templates > Windows Components > File Explorer > Turn off display of recent search entries in the File Explorer search box** to **Enabled.**

# Defender / Smartscreen

Disable Automatic Sample Submission.

If not using Smart App Control, disable Check Apps and Files.

# Edge Optional Features

Go through `edge://settings/privacy` and disable all optional features as well as Smartscreen for Edge.

# Widgets / Live Tiles 

These make potentially unneeded connections back to Microsoft, but from what I've seen they do not appear to send sensitive user data back. However, if you wish to disable them:

**Computer Configuration > 	Windows Components > Widgets > AllowWidgets** should be set to **Disabled**.


# Debloating

There are several things to put up with on Windows:

- Manufacturer bloatware, such as preinstalled third party ~~malware~~ antiviruses
- Start Menu shortcuts which are pinned by default
- Preinstalled third party apps such as Spotify
- Microsoft apps that you don't like

Manufacturer bloatware usually isn't too much of a problem if you're doing a clean install, though OEMs can and have abused WPBT to get around this.

Start menu shortcuts and preinstalled third party apps can be easily removed by right clicking and unpinning / uninstalling them.

Microsoft Apps such as Cortana can be removed using the `winget` package manager.

Do not download third party debloater tools.

# Security Stuff

- [ ] Make Sure everything is up to date! 
- [ ] Keep Camera / Mic / Location off when not in use
- [ ] Set UAC to the max, and consider using a non admin user 
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

# MDAG / Windows Sandbox





