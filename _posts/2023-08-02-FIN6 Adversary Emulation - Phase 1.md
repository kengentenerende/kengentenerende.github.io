---
title: FIN6 Adversary Emulation - Phase 1
date: 2023-08-02 09:23:59 +0800
categories: [Adversary Emulation, FIN6]
tags: [threathunt,metasploit]
---

## FIN6 Overview

FIN6 is thought to be a financially motivated cyber-crime group. The group has aggressively targeted and compromised high-volume POS systems in the hospitality and retail sectors since at least 2015. FIN6 has targeted e-commerce sites and multinational organizations. Most of the group’s targets have been located in the United States and Europe, but include companies in Australia, Canada, Spain, India, Kazakhstan, Serbia, and China.

## Step 1 - FIN6 Initial Access

### 1.1 - Phishing: Spearphishing Attachment [**T1566.001**](https://attack.mitre.org/techniques/T1566/001/)

As FIN6 appears to be monetarily motivated, they take a pragmatic approach toward delivery. FIN6 has employed social engineering ala direct messages on LinkedIn, spear-phished, compromised e-commerce sites, and it has been suggested that they have negotiated or even purchased access to previously compromised networks. 

### 1.1 - C2 Framework

FIN6 has made use of CobaltStrike and Metasploit. For this demonstration, we'll create initial payload using Metasploit’s [**Msfvenom**](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html).

_MSFvenom_ is a combination of Msfpayload and Msfencode, putting both of these tools into a single Framework instance. The advantages of Msfvenom are:

One single tool
Standardized command line options
Increased speed

Msfvenom has a wide range of options available:

```
Options:
    -p, --payload            Payload to use. Specify a '-' or stdin to use custom payloads
        --payload-options            List the payload's standard options
    -l, --list          [type]       List a module type. Options are: payloads, encoders, nops, all
    -n, --nopsled             Prepend a nopsled of [length] size on to the payload
    -f, --format              Output format (use --help-formats for a list)
        --help-formats               List available formats
    -e, --encoder            The encoder to use
    -a, --arch                  The architecture to use
        --platform          The platform of the payload
        --help-platforms             List available platforms
    -s, --space               The maximum size of the resulting payload
        --encoder-space       The maximum size of the encoded payload (defaults to the -s value)
    -b, --bad-chars             The list of characters to avoid example: '\x00\xff'
    -i, --iterations           The number of times to encode the payload
    -c, --add-code              Specify an additional win32 shellcode file to include
    -x, --template              Specify a custom executable file to use as a template
    -k, --keep                       Preserve the template behavior and inject the payload as a new thread
    -o, --out                   Save the payload
    -v, --var-name              Specify a custom variable name to use for certain output formats
        --smallest                   Generate the smallest possible payload
    -h, --help                       Show this message
```


## Step 2 - FIN6 Discovery

FIN6

## Step 3 - FIN6 Privilege Escalation

FIN6

## Step 4 - FIN6 Collection and Exfiltration

FIN6

## References

<https://www.offsec.com/metasploit-unleashed/msfvenom/>
