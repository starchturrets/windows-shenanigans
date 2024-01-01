# Configuring Windows 11 Pro/Enterprise 

(Read the whole guide before going through with it please!)
Disclaimer: I am not a security researcher, I simply read documentation, played around a bit with VMs, and talked to people in various privsec matrix channels. This is by no means comprehensive and/or a guarantee of privacy and security on Windows, as it is very much still a Work in Progress.

## Things to note before installing
 
- [ ] Does your device officially support Windows 11? Even if supported, certain features in the firmware settings on some older devices, such as TPM or secure boot, may be disabled by default and must be toggled on. [Look for a "PTT" setting for Intel devices and "fTPM" for AMD ones.](https://nitter.woodland.cafe/dwizzzleMSFT/status/1408144290954366976#m) While it is technically possible to [bypass the requirements and install on unsupported hardware](https://support.microsoft.com/en-us/windows/installing-windows-11-on-devices-that-don-t-meet-minimum-system-requirements-0b2dc4a2-5933-4ad4-9c09-ef0a331518f1), you may want to consider a Linux distro. 
- [ ] If you're not planning on dualbooting, and your device gives you the option to, disable the Microsoft UEFI CA in the secure boot settings. This will slightly improve boot security because instead of trusting the many bootloaders signed by it you will only be trusting Windows and your OEM certificates.   
- [ ] Does your OEM/Motherboard manufacturer provide you with bloatware delivered through the WPBT? (Example: Asus Armory Crate). There may be an option in the firmware to disable it.
- [ ] You may also have to enable virtualization support in the firmware settings for windows to take advantage of it, on certain devices this may not be on by default

## On Install

It is best not to login to a Microsoft Account on Windows. This is because of all the sync stuff that is toggled on by default. While not impossible to control, it's an annoyance that's best avoided. In addition, certain group policies for Edge do not apply to logged in users. Finally, according to [this study](https://web.archive.org/web/20230717045727/https://www.autoriteitpersoonsgegevens.nl/uploads/imported/public_version_dutch_dpa_informal_translation_summary_of_investigation_report.pdf), more device identifiers are sent with telemetry when logged into a Microsoft Account (see pages 5 through 7).

To skip the login, select **Set up for work or school > Sign-in Options > Domain Join**.

Go through the OOBE and opt out of everything:

- [ ] **Let Microsoft and apps use your location > No**
- [ ] **Find my device > No**
- [ ] **Send diagnostic data to Microsoft > Required only**
- [ ] **Improve inking & typing > No**
- [ ] **Get tailored experiences with diagnostic data > No**
- [ ] **Let apps use advertising ID > No**

If you are on Enterprise, you can stop Windows from pestering you to login to a Microsoft account by opening the group policy editor and enabling **Computer Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off Microsoft consumer experiences.**

If on Pro go to **System > Settings > Notifications > Additional Settings** and untick all the checkboxes there. This goes for new user accounts as well.

- [ ] **Show the Windows welcome experience after updates and when signed in to show what's new and suggested**
- [ ] **Suggest ways to get the most out of Windows and finish setting up this device**
- [ ] **Get tips and suggestions when using Windows**

## Things that phone home to Microsoft

This section is based off of limited testing in a VM, along with documentation from Microsoft:

https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services

https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints

Also, you can just auto apply the below group policies that turn off phone homey stuff with [LGPO](https://github.com/starchturrets/windows-shenanigans/tree/main/policies). 

Based off what I've seen, these are the more relevant items:

1. OS Diagnostics
2. Windows Spotlight
3. Bing Start Menu / Copilot 
4. Edge 
5. Certain aspects of Windows Defender (Automatic Sample Submission, Reputation Based Checks)
6. (Optional) Widgets and Live Tiles, Windows Media Player 

## OS Diagnostics (Sends back hardware data, among other things)

If you are on Pro, you cannot fully disable OS diagnostics. Select required diagnostics only in the OOBE and do not attempt to download third party tools that claim to disable telemetry.

<details>

<summary>If you are on Enterprise </summary>

If on Enterprise, open the group policy editor and go to **Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds.** 

Double-click **Allow Telemetry (or Allow diagnostic data on Windows 11 and Windows Server 2022).**

Select the "Send no Diagnostic Data" Option, then click OK to apply changes.

</details>

## Windows Spotlight

Windows Spotlight sends back similar hardware data to required diagnostics. To turn it off:

- [ ] Enable the following Group Policy **User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off all Windows spotlight features.**

- [ ] Enable the following Group Policy **Computer Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off cloud optimized content.**

According to Microsoft docs, this must be done within **15 minutes of first install.** The first policy is also restricted to Enterprise/Education installs only.

If you are on Pro, you can't fully turn off spotlight. You can still turn off the daily lockscreen images in settings (has to be done for every new user account):

- [ ] **Personalization > Lock Screen > Personalize your lock screen > Picture**
- [ ] Untick **Get fun facts, tips, tricks, and more on your lock screen**

 You can also disable the daily wallpaper images entirely in group policy, and disallow diagnostic data from being used for tailored experiences (applies machine wide):  
 
- [ ] Enable **User Configuration > Administrative Templates > Windows Components > Cloud Content > Turn off Spotlight collection on Desktop.**
- [ ] Enable **User Configuration > Administrative Templates > Windows Components > Cloud Content > Do not use diagnostic data for tailored experiences.**

## Bing Start Menu / Copilot

By default, the start menu search searches the web, which leaks your local file queries to Microsoft. Copilot is also annoying.

- [ ] Enable **User Configuration > Administrative Templates > Windows Components > File Explorer > Turn off display of recent search entries in the File Explorer search box**
- [ ] Enable **User Configuration > Administrative Templates > Windows Components > Windows Copilot​ > Turn off Windows Copilot** to **Enabled**.


## Defender

### Virus and Threat Protection settings: 

https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission?view=o365-worldwide#how-cloud-protection-and-sample-submission-work-together

Defender's cloud protection relies on collecting metadata about suspicious files (both executable and non executable), which ostensibly assists it in determining if said file is malicious or not (See the link for examples of what metadata is collected). Should this not be enough, it will upload, or request to upload the file for further analysis. The default appears to be to automatically upload the file if it is executable, and therefore unlikely to contain PII (as opposed to say, PDFs or DOCX files). Otherwise, it will prompt the user for consent.

There are two options for handling this:

1. Limit what data is sent to Microsoft, and accept the reduced security due to defender being less effective
2. Allow Microsoft to collect some metadata and the occassional executable sample in exchange for security

Which option you go with is dependent on your threat model. For example, the latter option might be preferable if you use the windows install purely for gaming.

To go with the former option, disable both cloud protection and automatic sample submission.

Go to **Windows Security > Virus and Threat Protection > Manage Settings > Automatic Sample Submission.**
Click to disable it. 

## Smart App Control 

Smart App Control (and Smartscreen in general) is a tradeoff between privacy and security. On the one hand, it improves security by using reputation checks to make sure legitimate files are not blocked while blocking malware, on the other hand it needs to send file metadata to Microsoft in order to function. As the Microsoft Privacy Policy puts it: 

> Where supported, Smart App Control helps check software that is installed and runs on your device to determine if it is malicious, potentially unwanted, or poses other threats to you and your device. **On a supported device, Smart App Control starts in evaluation mode and the data we collect for Microsoft Defender SmartScreen such as file name, a hash of the file’s contents, the download location, and the file’s digital certificates, is used to help determine whether your device is a good candidate to use Smart App Control for additional security protection.** 

> ...

> When either Microsoft Defender SmartScreen or Smart App Control checks a file, data about that file is sent to Microsoft, including the file name, a hash of the file’s contents, the download location, and the file’s digital certificates.

It is ultimately up to you whether or not to use it (more on that below).

If you have chosen to not use Smart App Control, go to **Windows Security > App and Browser Control > Check Apps and Files** and disable it.

Even if you have chosen to use SAC/Smartscreen, it is probably the best to also disable **Smartscreen for Microsoft Edge**, as it has been shown to leak full URLs and browsing history to Microsoft. 

## Edge 

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

This is an extremely silly way to do it imo when Google safe browsing has shown it's possible to implement it in a safe way without blasting all the URLs you visit away to Microsoft. Testing with `mitmproxy` also indicates that with Edge smartscreen on, URLs are presently leaked to them.

 Turn off **everything** under the Services section, and check it every update. They have been found to leak data multiple times. The only thing that might be ok is Services > Use a web service to help resolve navigation errors, which only seems to be used for captive portals.


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


## Widgets, Windows Media Player 

These make potentially unneeded connections back to Microsoft, but from what I've seen they do not appear to send sensitive user data back. However, if you wish to disable them:

**Computer Configuration > 	Windows Components > Widgets > AllowWidgets** should be set to **Disabled**.

Alternatively, Widgets can be uninstalled by doing `winget uninstall "Windows Web Experience Pack"` in an elevated PowerShell window. 

The Windows Media Player uses Bing by default to auto fetch Music metadata. This can be disabled by opening the app, going to settings, and toggling off "Search for missing Album and Artist art online".

## Debloating

There are several things to put up with on Windows:

- Manufacturer bloatware, such as preinstalled third party ~~malware~~ antiviruses
- Start Menu shortcuts which are pinned by default
- Microsoft apps that you don't like

Manufacturer bloatware usually isn't too much of a problem if you're doing a clean install, though OEMs can and have abused WPBT as well as driver updates to get around this.

Windows Plug and Play auto installers (which on top of being potential bloat have led to privilege escalation bugs in the past) can be disabled by setting: 

**Computer Configuration > Administrative Templates > System > Device Installation > Prevent device metadata retrieval from the Internet** to **Enabled**.

Note: the proper way to disable it is documented at https://www.bleepingcomputer.com/news/microsoft/how-to-block-windows-plug-and-play-auto-installing-insecure-apps/, this gpo [doesn't actually fully disable co installers executed as part of the driver.](https://mastodon.social/@faebudo@ioc.exchange/111499421425476615)

Start menu shortcuts and preinstalled third party apps can be easily removed by right clicking and unpinning / uninstalling them.

Microsoft Apps such as Cortana can be removed using the `winget` package manager.

1. Open an elevated powershell window and type in `winget list`
2. Copy the name of the package you wish to uninstall and type in `winget uninstall PACKAGE_NAME`

Note that uninstalling Cortana does not remove the need to apply the above group policies regarding Cortana and Search. You also cannot uninstall Microsoft Edge.  Do not go overboard uninstalling system apps in case you break something, and *please*, do not download third party debloater tools.

## Improving Security

- [ ] Make Sure everything is up to date! 
- [ ] Keep Camera / Mic / Location off when not in use with global killswitches
- [ ] Set UAC to "Always Notify", and consider daily driving a standard user account
- [ ] Use `winget` to manage apps where possible
- [ ] Enable supported hardware security features 
- [ ] Enable Controlled Folder Access 
- [ ] Turn on Smart App Control, or use a WDAC policy to somewhat mimic Smart App Control's functionality while adding a bit more flexibility
- [ ] Use VMs to run untrusted executables (Hyper V / MDAG / Windows Sandbox)
- [ ] Improve Office security with ASR rules and Security Baselines
- [ ] Configure Bitlocker
- [ ] Apply the BlackLotus secure boot revocations
- [ ] Use admx group policies to improve Edge security
  
## Keep Everything Updated

Check your Windows Update settings page regularly, especially on the second Tuesday of each month, as Microsoft usually releases security updates then ("Patch Tuesday").

Windows can also automatically update certain Microsoft products such as Office through windows update, though in my experience this isn't perfect.

Also check "Optional Updates" for driver and firmware updates. However, in some cases the drivers provided by Windows Update are old, and it is better to use the OEM tool to update drivers. This goes for AMD devices.  

Winget can update some apps, but not those from the Microsoft Store, so you'll have to check things there separately.

## Camera / Mic / Location

Due to currently terrible permission control, not all apps can be denied the camera or mic permission. So keep the global toggle disabled when not in use, which should turn it off for legacy desktop apps as well. Note that apps with admin access can override this setting.

## User Account Control

Set UAC to the highest level: type "UAC" into the start menu, click the settings result that shows up, and move the slider up to the "Always notify" level. This will mitigate *some* [bypasses](https://www.bleepingcomputer.com/news/security/old-windows-mock-folders-uac-bypass-used-to-drop-malware/). However, UAC is **not** considered a [security boundary](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria) by Microsoft. The best option is to daily drive a standard user account, and switch into the admin account only when absolutely needed. 

While having to authenticate to elevate is an inconvenience, you can mitigate this somewhat by using a relatively short Windows Hello PIN or biometrics. While it may seem less secure to have a short pin, this is backed by the TPM, which should enforce ratelimiting. (See: these [two](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-why-pin-is-better-than-password#pin-is-backed-by-hardware) documentation [articles](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/how-windows-uses-the-tpm) from Microsoft Learn about it.)

By default, Windows forces you to set security questions for a new local account, as well as go through the OOBE again. To disable:

- [ ] Enable the following group policy: **Computer Configuration > Administrative Templates > Windows Components > Credential User Interface > Prevent the use of security questions for local accounts**
- [ ] Enable the following group policy **Computer Configuration > Administrative Templates > Windows Components > OOBE > Don't launch privacy settings experience on user logon**

## App Management

Rather than using a search engine to look for and download app - which is prone to being gamed by [malicious sites](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-to-spread-malware-in-legit-software/), it is preferable to use the `winget` package manager which comes preinstalled on Windows 11 by default. To look for a package, open up a terminal window and type in `winget search "Package Name"`. You can then verify the publisher (which is handy for Microsoft Store apps) by copying the application ID and running `winget show "application ID"`. 

According to [this](https://github.com/microsoft/winget-cli/discussions/2534) winget packages (community packages, the Store is larger and lets shady stuff slip through) do go through some amount of manual review before being added in:

> I don't see where security risks would be an issue here because every installer goes through Dynamic Analysis (Virus Scan) in the Pipelines' VMs, and if there's a PUA or malware in the installer, it's immediately flagged by the pipelines. The PR is also manually validated by Moderators, in either VMs, or Bare Metal - so installers are always double checked to make sure that it isn't a malicious package intended to steal people's passwords or monitor what they're typing on their keyboard.
Even if the pipelines cannot catch the malware issue, depending on the antivirus software someone has, all installers from WinGet are downloaded to %TEMP%\WinGet, except for .appx(bundle) and .msix(bundle), where your antivirus software will probably scan it before it's executed to install it onto your PC.

While this is by no means a guarantee, this should reduce the chances of getting served outright malware.

Occasionally an app will show up as being downloadable from either the Store or the publisher website. Currently there does not seem to be any major security difference between the two (aside from making WDAC Configuration somewhat harder), so it is up to the user to decide which to install.  

Microsoft Store apps can be sandboxed, however **just because an app is on the Store does not mean it is sandboxed**. Check the permissions page and make sure that an app does not have the "Use All System Resources" permission if you wish for it to be sandboxed. 

When possible, avoid running unsigned apps. 

# Virtualization Based Security and related settings

https://support.microsoft.com/en-us/windows/device-protection-in-windows-security-afa11526-de57-b1c5-599f-3a4c6a61c5e2

Check the device security section, scroll to the bottom.

If it says: "Standard hardware security not supported":

- [ ] Your device does not support Windows 11 at all
- [ ] There is a feature (such as secure boot or the TPM) that must be toggled in the firmware settings
- [ ] It is a Windows Security bug - in which case you can manually validate by checking `msinfo32.exe`

Once you see "Your device meets the requirements for standard hardware security", you can then go to **Core Isolation** and toggle on Memory Integrity, as well as the Microsoft Vulnerable Driver Blocklist. In some cases, Windows 11 auto enables it on clean install, but this is not guaranteed. After a reboot, the bottom of the device security section should then say "Your device meets the requirements for enhanced hardware security".

The group policies can be found under **Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security**.

- [ ] Select Platform Security Level: Secure Boot (this will enable as much protection as is supported, [unlike the Secure Boot with DMA option](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#use-registry-keys-to-enable-memory-integrity))
- [ ] Select Virtualization Based Protection of Code Integrity and set it to Enabled Without UEFI Lock
- [ ] Tick "Require UEFI Memory Attributes Table"
- [ ] Credential Guard seems to be oriented towards mitigating an attacker from moving laterally within an enterprise network, so prolly best to leave it at not configured as it doesn't seem that relevant to a home user (also, it's a windows enterprise only thing anyways)
- [ ] [Secure Launch](https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection) is a secured core thing, if you did not see "Firmware Protection" in the core isolation settings page, leave the policy at not configured as it's unsupported anyways.
- [ ]  Kernel-mode hardware-enforced stack protection is also hardware dependent, do not configure it if you didn't see it in the core isolation settings page

After configuring policies, reboot and check the core isolation settings page. If memory integrity has turned off, then that means that [UEFI MAT](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) is not supported by the firmware. Untick the policy for it. Then, you can set Virtualization Based Protection of Code Integrity to enabled with UEFI Lock, and reboot. This will mitigate a remote attacker with admin access from simply forcing it off. You can test this for yourself by setting the policy to disabled and rebooting - memory integrity will still be reported as on. The only way to disable it appears to be by having physical access and disabling secure boot, or by having a [secure boot exploit](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/). 

## Smart App Control
 
Windows offers several methods to stop untrusted executables from running, such as AppLocker or Smart App Control / WDAC. Each of them have their own advantages and disadvantages, but they do help mitigate attacks such as those from clicking on disguised executables.  

WDAC (Windows Defender Application Control) is what runs under the hood of Smart App Control, however SAC exposes far less configuration. SAC can be enabled on new installs by opening the Windows Security App and going to **App and Browser Control > Settings for Smart App Control** and selecting the Activated option.

While this means it is dead simple, it is also a blunt all or nothing - if a dll critical to signal desktop or another similar app is blocked, there is no option to allowlist it, only turn it off entirely, and it cannot be (officially) reenabled without reinstalling the OS. (This is [deliberate](https://nitter.woodland.cafe/dwizzzleMSFT/status/1723004632815837220#m)).

So, SAC is probably a good idea under the following conditions:

- You do not use WSL (sorry, that gets blocked!)
- You are not a programmer (generating lots of unsigned code doesn't play very well with it)
- You primarily use apps from Microsoft Store/winget that are unlikely to be blocked
- You are OK with Microsoft getting file metadata (see above)

If you only use a few basic apps, I recommend using SAC unless it's incompatible with your workflow. If you want to use it without reinstalling (for example, you only now use a limited set of apps but don't wanna go through the hassle of setup again), Microsoft does offer a way to [turn it back on](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control#configure-smart-app-control-using-the-registry) from the windows recovery environment.

## Microsoft Office

Unfortunately, unless you're on an Enterprise 365 Office subscription (unlikely) you will not be able to make use of MDAG like on Edge. That being said, there are still a few steps you can take to improve security on Office.

https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide

ASR rules can be found under: **Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction Rules.**

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

In addition, you can apply the [Microsoft 365 Security baselines for Enterprise.](https://learn.microsoft.com/en-us/deployoffice/security/security-baseline) It will disable the opening/saving of older file formats as well as unsigned script macros. This is not as strong of a security boundary as MDAG, but it should still be helpful for reducing attack surface. While tailored for Enterprise Office installs, many policies appear to also be applicable to others such as LTSC 2021.

The baseline can be downloaded from here: https://www.microsoft.com/en-us/download/details.aspx?id=55319. Make sure to select `LGPO.zip` as well. After unzipping both files, move `LGPO.exe` to the `\Scripts\Tools` subdirectory. You can then open an admin Powershell in the `\Scripts` subdirectory and run:

```
 powershell.exe -ExecutionPolicy unrestricted .\Baseline-LocalInstall.ps1
```

(or `pwsh.exe`, depending on what you have installed).

After running, reboot.

Administrative templates (should you wish to override a setting from the group policy editor or have them show up in your GPReport) can be downloaded from here: https://www.microsoft.com/en-us/download/details.aspx?id=49030. 


## Windows Sandbox for untrusted files

- Make sure you meet the prerequisites for installation: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview#prerequisites
- If so, you can enable it by going to Turn Windows Features on or off > Windows Sandbox. Select it, click ok, then restart the computer if prompted.

You can then use it to open PDFs and other document files you're not sure about.

Windows Sandbox is more oriented towards being a temporary throwaway VM, and it does come with some caveats: 

- Malware can detect it's running in a VM, and not do anything suspicious until it's on the host.
- Malware can detect it's running in a VM, [and overwrite the clipboard with a malicious executable to get it onto the host.](https://github.com/fractureiser-investigation/fractureiser/blob/main/docs/tech.md#anti-sandbox-tricks)

So, be careful when copy/pasting files out of it, and don't treat it as a guarantee that an executable isn't malware. 

This is a bit more experimental, but it's possible to configure Windows Sandbox to auto install LibreOffice while passing through the Downloads folder:


```
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Users\Admin\Sandboxing\Office Apps\LibreOffice\</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\LibreOffice\</SandboxFolder>
      <ReadOnly>True</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>C:\Users\Admin\Downloads\</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Downloads\</SandboxFolder>
      <ReadOnly>False</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>msiexec.exe /I C:\Users\WDAGUtilityAccount\LibreOffice\LibreOffice_7.5.5_Win_x86-64.msi /quiet</Command>
    <Command></Command>  
</LogonCommand>
<ProtectedClient>True</ProtectedClient>
</Configuration>
```

While being a relatively simple `.wsb` file, it has the disadvantage of taking about a minute to install each time the sandbox instance is started.

## Bitlocker

https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-countermeasures

By default, bitlocker is only setup to protect against "casual" physical access, this is likely enough for most people's threat model (tampering is most likely irrelevant if a thief steals your device to wipe it and resell it, your data would still be protected). 

So, turning on bitlocker from the settings menu should be enough. 

As bitlocker uses AES-128 by default, you can strengthen it by going to **Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Choose drive encryption method and cipher strength** and setting it to XTS-AES 256 before encrypting.

**Backup your recovery key.**

This is *extremely* important. Sometimes after firmware updates, you might be prompted to enter it in (more on that later).

However, there have been [attacks against bitlocker's TPM authentication, and it is by no means perfect](https://github.com/Wack0/bitlocker-attacks). Also, there are [issues with how Windows Hello biometrics is currently implemented by OEMs](https://blackwinghq.com/blog/posts/a-touch-of-pwn-part-i/). Should you wish to go the extra mile and deter against more than the "casual" physical attacker, you will have to take the following measures:

- Use an enhanced PIN in addition to the TPM for pre boot authentication
- Disable standby power management and shut down/hibernate before leaving the device unattended
- Use legacy integrity validation, and pin Bitlocker to PCRs 0, 2, 4, 7, and 11.


## BlackLotus Revocations

https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d

1. Make sure your Windows install is fully up to date (has the July 11 2023 updates installed)
2. Enter the following into an elevated command prompt: `reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x30 /f`
3. Restart.
4. Wait five minutes.
5. Restart again.

Event IDs 1035 and 276 should be logged under the Windows Event Viewer.
