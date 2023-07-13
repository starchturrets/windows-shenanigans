# Configuring Windows 11 Pro/Enterprise 

(Read the whole guide before going through with it please!)

# Things to note before installing: 
 
- [ ] Does your device officially support Windows 11? Can Secure Boot and TPM be enabled in the firmware settings? CSM legacy boot mode should also be disabled. If not, do not attempt to bypass the hardware requirements, which provide much of the benefits of Windows 11 by allowing certain security features to be toggled on by default. If you're on an unsupported device and cannot upgrade, consider ChromeOS Flex or a Linux distro. 
- [ ] If you're not planning on dualbooting or running Linux, and your device gives you the option to, disable the Microsoft UEFI CA in the secure boot settings. This will improve boot security because instead of trusting hundreds of bootloaders you will only be trusting Windows (and your OEM) certificates.
- [ ] Does your OEM/Motherboard manufacturer provide you with bloatware delivered through the WPBT? There may be an option in the firmware to disable it.

# On Install:

It is best not to login to a Microsoft Account on Windows. (Note: add explanations why!) On Windows 11 Pro it is possible to skip the requirement to login by clicking on the “Set up for work or school” option -> Sign-in Options -> Domain Join.

Screenshots will be posted here when I get to testing in VMs.

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

If on Enterprise, 

# Bing Start Menu

# Windows Spotlight

# Defender / Smartscreen, hardening 

# Widgets / Live Tiles 

# Edge Optional Features

# Debloating
