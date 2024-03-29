Just my (very rough) notes about boot security on desktop

# Firmware

HSTI / HSI Level

Self tests done to show how much the firmware protects itself. Passing HSTI (see msinfo32 device encryption section) means Windows will do automatic encryption upon sign in to a Microsoft account.

Linux equivalent is doing `sudo fwupdmgr security` (can also be done on a live USB). Not sure what HSI level HSTI passing is equivalent to - HSI 2? 

# Intel Bootguard / AMD Platform Secure Boot

# Intel ME / AMD PSP

# TPMs

fTPMs vs discrete TPMs, Pluton, uses?


TPM uses in a non enterprise environment:
- Bitlocker
- Windows Hello PIN ratelimiting
- Passkey storage?

# Secure Boot

- Trusted certs - Windows vs Microsoft certs, issues with revoking things signed by them (Blacklotus and Boothole respectively) 

# Bitlocker

 PCR 7 binding vs 0, 2, 4, and 11. Explain why firmware updates often lead to recovery screens. 
# OEM Nonsense

- MSI
- Dell
