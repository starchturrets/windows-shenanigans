# Group Policy deployment with LGPO

Since it is a pain to configure dozens of group policies manually, here is a way to apply them automatically.

1. Download and extract the policies.zip from the releases section.
2. Open the policies directory in an elevated powershell Terminal.
3. Read through the `machine.txt` and `user.txt` files to see what settings are being applied.
4. You can verify that the `LGPO.exe` is legitimate by right clicking and checking the digital signature, but if you don't trust me you can download it from [Microsoft](https://www.microsoft.com/en-US/download/details.aspx?id=55319) (click on Download and select LGPO.zip).
5. Build the policy files by running
```
    .\LGPO.exe /r .\machine.txt /w .\machine.pol
    .\LGPO.exe /r .\user.txt /w .\user.pol
```
6. Apply the policies by running 
```
    .\LGPO.exe /m .\machine.pol
    .\LGPO.exe /u .\user.pol
```
(Note that you have to run the second line for every new user account created.)

7. Reboot
