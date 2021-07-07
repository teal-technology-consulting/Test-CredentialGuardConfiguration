# Test-CredentialGuardConfiguration
This project includes the following items:

* A PowerShell script that checks if [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard) is active and collects system data for further analysis. It performs the following activities:
  * Checks for the Credential Guard configuration in the following locations:
    * Registry key **HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard**
    * Registry key **HKLM\SYSTEM\CurrentControlSet\Control\LSA**
    * WMI class **root\Microsoft\Windows\DeviceGuard\Win32_DeviceGuard**
    * Various events in the event log
  * Checks if the process **LsaIso** is running.
  * Collects various events from the event logs for further diagnostics.

* Two MOF files that [extend](https://docs.microsoft.com/en-us/mem/configmgr/core/clients/manage/inventory/extend-hardware-inventory) Microsoft Endpoint Configuration Manager inventory for collecting Credential Guard configuration information. This information can then be displayed with a web browser using Configuration Manager Reporting.
  * The contents of the file **CredentialGuard_configuration.mof** must be added to the existing file **Configuration.mof** in the directory **\<CMInstallLocation\>\\Inboxes\\clifiles.src\\hinv\\**.
  * The contents of the file **CredentialGuard_SMS_DEF.mof** must be added to the **Default Client Settings**. 
