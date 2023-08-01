---
title: Getting Started with Kali Purple - Installing Elastic Stack
author: keng
date: 2023-08-01  09:23:59 +0800
categories: [Kali Purple]
tags: [kalipurple]
---

## What is Kali Purple?

![]({{site.baseurl}}/assets/img/Kali-Purple-banner-2023.1-release.jpg){:width="100%"}

Kali Linux, the popular Debian-based Linux distribution designed for digital forensics and penetration testing, announced a new project named [**Kali Purple**](https://gitlab.com/kalilinux/kali-purple/documentation/-/wikis/home), a distro designed for defensive security.

On a high level, Kali Purple consists of:

Over 100 defensive tools, such as:

- Arkime full packet capture
- Cyberchef
- Elasticsearch SIEM
- GVM vulnerability scanner
- TheHive incident response platform
- Malcolm
- Suricata IDS
- Zeek IDS
- and of course all the usual Kali tools


ISOs:

- Kali Purple
- Malcolm - based on Kali
- Hedgehog - based on Kali


A defensive menu structure according to NIST CSF:

- Identify
- Protect
- Detect
- Respond
- Recover


A gorgeous wallpaper and theme
A reference architecture for the ultimate SOC In-A-Box; perfect for:

- Learning
- Practicing SOC analysis and threat hunting
- Security control design and testing
- Blue / Red / Purple teaming exercises
- Kali spy vs. spy competitions ( bare knuckle Blue vs. Red )


Kali Autopilot - an attack script builder / framework for automated attacks
Defensive tools documentations
Wiki
Kali Purple Hub for the community to share:

- Practice pcaps
- Kali Autopilot scripts for blue teaming exercises


Kali Purple Discord channels for community collaboration and fun

## Installation

Initially, refer to the comprehensive installation instructions for Kali Purple on VMWare Workstation, which were provided by [**@JonGoodCyber**](https://www.youtube.com/@JonGoodCyber)
{% include embed/youtube.html id='y6s0B3LGRZw' %}

## Setting-up Elastic Stack

In this article, I’ll walk you through the deployment of Elasticsearch SIEM (Security Information and Event Management) with Kibana on Kali Purple.

<https://gitlab.com/kalilinux/kali-purple/documentation/-/blob/main/301_kali-purple/installation.txt>


## 1. Install Dependencies

```bash
sudo apt-get install curl
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic-archive-keyring.gpg
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list
sudo bash -c "export HOSTNAME=kali-purple.kali.purple; apt-get install elasticsearch -y"
```

The default username is _elastic_. Additionally, ensure that you save the password, which can be found under _Security AutoConfiguration Information_.
![]({{site.baseurl}}/assets/img/2023-08-01-Getting Started with Kali Purple - Installing Elastic Stack/2023-08-01-Security_AutoConfiguration_information.png){:width="100%"}

## 2. Convert to Single-Node Setup

```bash
sudo sed -e '/cluster.initial_master_nodes/ s/^#*/#/' -i /etc/elasticsearch/elasticsearch.yml
echo "discovery.type: single-node" | sudo tee -a /etc/elasticsearch/elasticsearch.yml
```

## 3. Install Kibana

```bash
sudo apt install kibana
sudo /usr/share/kibana/bin/kibana-encryption-keys generate -q
```

Add keys to <kbd>/etc/kibana/kibana.yml</kbd>

```bash
echo "server.host: \"kali-purple.kali.purple\"" | sudo tee -a /etc/kibana/kibana.yml
```

![]({{site.baseurl}}/assets/img/2023-08-01-Getting Started with Kali Purple - Installing Elastic Stack/2023-08-01-Bind_Internal_IP.png){:width="700"}

Ensure that kali-purple.kali.purple is only mapped to the IP address of your Kali Purple Machine in <kbd>/etc/hosts</kbd> in order to bind the Kibana interface.
![]({{site.baseurl}}/assets/img/2023-08-01-Getting Started with Kali Purple - Installing Elastic Stack/2023-08-01-Security_AutoConfiguration_information.png){:width="700"}

Once done, you can now start Elasticsearch and Kibana.

```bash
sudo systemctl enable elasticsearch kibana --now
```

[**Real Favicon Generator**](https://realfavicongenerator.net/)

Prepare a square image (PNG, JPG, or SVG) with a size of 512x512 or more, and then go to the online tool [**Real Favicon Generator**](https://realfavicongenerator.net/) and click the button <kbd>Select your Favicon image</kbd> to upload your image file.

In the next step, the webpage will show all usage scenarios. You can keep the default options, scroll to the bottom of the page, and click the button <kbd>Generate your Favicons and HTML code</kbd> to generate the favicon.

## Download & Replace

Download the generated package, unzip and delete the following two from the extracted files:

- `browserconfig.xml`{: .filepath}
- `site.webmanifest`{: .filepath}

And then copy the remaining image files (`.PNG`{: .filepath} and `.ICO`{: .filepath}) to cover the original files in the directory `assets/img/favicons/`{: .filepath} of your Jekyll site. If your Jekyll site doesn't have this directory yet, just create one.

The following table will help you understand the changes to the favicon files:

| File(s)             | From Online Tool                  | From Chirpy |
|---------------------|:---------------------------------:|:-----------:|
| `*.PNG`             | ✓                                 | ✗           |
| `*.ICO`             | ✓                                 | ✗           |

>  ✓ means keep, ✗ means delete.
{: .prompt-info }

The next time you build the site, the favicon will be replaced with a customized edition.
