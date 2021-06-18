# MemProcFS-Analyzer
MemProcFS-Analyzer.ps1 is a PowerShell script utilized to simplify the usage of MemProcFS and to assist with the memory analysis workflow.

MemProcFS - The Memory Process File System by Ulf Frisk  
https://github.com/ufrisk/MemProcFS  

Features:
* Auto-Install of MemProcFS, Elasticsearch, Kibana, EvtxECmd, AmcacheParser, AppCompatCacheParser, RECmd, SBECmd, ImportExcel, and IPinfo CLI  
* Auto-Update of MemProcFS, Elasticsearch, Kibana, ClamAV Virus Databases (CVD), EvtxECmd (incl. Maps), AmcacheParser, AppCompactCacheParser, RECmd, SBECmd, Import-Excel, and IPinfo CLI
* Update-Info when there's a new version of ClamAV or a new Redistributable packaged Dokany Library Bundle available  
* Multi-Threaded scan w/ ClamAV for Windows  
* OS Fingerprinting  
* Collection of injected modules detected by MemProcFS PE_INJECT for further analysis (PW: infected)
* Extracting IPv4/IPv6  
* IP2ASN Mapping and GeoIP w/ [IPinfo CLI](https://github.com/ipinfo/cli)  
* Checking for Unusual Parent-Child Relationships and Number of Instances  
* Extracting Windows Event Log Files and processing w/ EvtxECmd &#8594; Timeline Explorer ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing extracted Amcache.hve w/ Amcacheparser ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing Application Compatibility Cache aka ShimCache w/ AppCompatcacheParser ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing Syscache w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing UserAssist Artifacts w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Analyzing ShellBags Artifacts w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Extracting Auto-Start Extensibility Points (ASEPs) w/ RECmd ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman) 
* Integration of PowerShell module [ImportExcel](https://github.com/dfinke/ImportExcel) by Doug Finke
* Collecting Evidence Files (Secure Archive Container &#8594; PW: MemProcFS)  

## Download 
Download the latest version of **MemProcFS-Analyzer** from the [Releases](https://github.com/evild3ad/MemProcFS-Analyzer/releases) section.  

## Usage  
Launch Windows PowerShell (or Windows PowerShell ISE or Visual Studio Code w/ PSVersion: 5.1) as Administrator and open/run MemProcFS-Analyzer.ps1. 

![File-Browser](https://github.com/evild3ad/MemProcFS-Analyzer/blob/195b43a37a11e58998d03213717f70e22c6bae54/Screenshots/01.png)  
**Fig 1:** Select your Raw Physical Memory Dump (File Browser)

![Auto-Install](https://github.com/evild3ad/MemProcFS-Analyzer/blob/195b43a37a11e58998d03213717f70e22c6bae54/Screenshots/02.png)  
**Fig 2:** MemProcFS-Analyzer auto-installs multiple dependencies (First Run)

![Microsoft-Internet-Symbol-Store](https://github.com/evild3ad/MemProcFS-Analyzer/blob/195b43a37a11e58998d03213717f70e22c6bae54/Screenshots/03.png)  
**Fig 3:** Accept Terms of Use (First Run)  

![MemProcFS](https://github.com/evild3ad/MemProcFS-Analyzer/blob/195b43a37a11e58998d03213717f70e22c6bae54/Screenshots/04.png)  
**Fig 4:** If you find MemProcFS useful, please become a sponsor at: https://github.com/sponsors/ufrisk  

![Auto-Update](https://github.com/evild3ad/MemProcFS-Analyzer/blob/195b43a37a11e58998d03213717f70e22c6bae54/Screenshots/05.png)  
**Fig 5:** MemProcFS-Analyzer checks for dependencies (Second Run)

![ClamAV-Scan](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d4b43171c4dacaf42cd983b5ea9810ba29e0bd7e/Screenshots/ClamAV-Scan.png)  
**Fig 6:** Multi-Threaded ClamAV Scan

![IPinfo](https://github.com/evild3ad/MemProcFS-Analyzer/blob/28d128fdf058b056e929dd925433edfd2f10cbfd/Screenshots/IPinfo.png)  
**Fig 7:** GeoIP w/ IPinfo.io

![IPinfo](https://github.com/evild3ad/MemProcFS-Analyzer/blob/e5505296fd5ea604af15f4882a5478a44160f321/Screenshots/Map.png)  
**Fig 8:** Map IPs w/ IPinfo.io

![Elasticsearch](https://github.com/evild3ad/MemProcFS-Analyzer/blob/e804fa5bd5195757a5a36d9bed8aa04b83dbbcca/Screenshots/EventLogs.png)  
**Fig 9:** Processing Windows Event Logs (EVTX)

![Amcache](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d547838fe2320e8812b3c4c3000a581c9a0e350c/Screenshots/Amcache.png)  
**Fig 10:** Processing extracted Amcache.hve &#8594; XLSX  

![ShimCache](https://github.com/evild3ad/MemProcFS-Analyzer/blob/28d128fdf058b056e929dd925433edfd2f10cbfd/Screenshots/ShimCache.png)  
**Fig 11:** Processing ShimCache &#8594; XLSX  

![ELK-Import](https://github.com/evild3ad/MemProcFS-Analyzer/blob/662aace82f911c1248dee6cbcf4b3a6e78aa8d0d/Screenshots/ELK-Import.png)  
**Fig 12:** ELK Import

![ELK-Timeline](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/ELK-Timeline.png)  
**Fig 13:** Happy ELK Hunting!

![Secure-Archive-Container](https://github.com/evild3ad/MemProcFS-Analyzer/blob/e804fa5bd5195757a5a36d9bed8aa04b83dbbcca/Screenshots/Secure-Archive-Container.png)  
**Fig 14:** ClamAV Scan found 29 infected file(s)

![Message-Box](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/Message-Box.png)  
**Fig 15:** Press **OK** to shutdown MemProcFS and Elastisearch/Kibana

![Output](https://github.com/evild3ad/MemProcFS-Analyzer/blob/8d55333f9c89d120b76d454ce60fca167767ba2b/Screenshots/Output.png)  
**Fig 16:** Secure Archive Container (PW: MemProcFS)

## Prerequisites 
1. Download and install the latest Dokany Library Bundle (Redistributable packaged) &#8594; DokanSetup_redist.exe  
The Dokany installer will also install the required Microsoft Visual C++ Redistributables for Visual Studio 2019.  
https://github.com/dokan-dev/dokany/releases/latest  

2. Download and install the latest Windows package of ClamAV.  
https://www.clamav.net/downloads 

3. First Time Set-Up of ClamAV  
Launch Windows PowerShell console as Administrator.  
`cd "C:\Program Files\clamav"`  
`copy .\conf_examples\freshclam.conf.sample .\freshclam.conf`  
`copy .\conf_examples\clamd.conf.sample .\clamd.conf`  
`write.exe .\freshclam.conf`  &#8594; Comment or remove the line that says “Example”.  
`write.exe .\clamd.conf` &#8594; Comment or remove the line that says “Example”.  
https://www.clamav.net/documents/installing-clamav-on-windows  

4. Create your free IPinfo account [approx. 1-2 min]  
https://ipinfo.io/signup?ref=cli  
Open "MemProcFS-Analyzer.ps1" with your text editor, search for "access_token" and copy/paste your access token.

5. Install the NuGet package provider for PowerShell  
Check if NuGet is available in the package providers by running the following command:  
`Get-PackageProvider -ListAvailable`  
If NuGet is not installed on your system yet, you have to install it.  
`Install-PackageProvider -Name NuGet -Force`  

6. Done! :smiley:  

## Dependencies
7-Zip 9.20 Command Line Version (2010-11-18)  
https://www.7-zip.org/download.html  

AmcacheParser v1.4.0.0 (2021-03-20)  
https://binaryforay.blogspot.com/  

AppCompatCacheParser v1.4.4.0 (2021-03-20)  
https://binaryforay.blogspot.com/  

ClamAV - Windows Packages &#8594; Win64 &#8594; ClamAV-0.103.2.exe (2021-04-07)  
https://www.clamav.net/downloads  
https://www.clamav.net/documents/installing-clamav-on-windows &#8594; First Time Set-Up  

Dokany Library Bundle v1.4.0.1000 x64 (2020-06-01)  
https://github.com/dokan-dev/dokany/releases/latest &#8594; DokanSetup_redist.exe  

Elasticsearch 7.13.2 (2021-06-14)  
https://www.elastic.co/downloads/elasticsearch  

EvtxECmd v0.6.5.0 (2020-12-21)  
https://binaryforay.blogspot.com/  

ImportExcel 7.1.2 (2020-05-08)  
https://github.com/dfinke/ImportExcel  

Ipinfo CLI 2.0.0 (2021-05-26)  
https://github.com/ipinfo/cli  

Kibana 7.13.2 (2021-06-14)  
https://www.elastic.co/downloads/kibana  

MemProcFS v4.1.0 - The Memory Process File System (2021-06-13)  
https://github.com/ufrisk/MemProcFS  

Microsoft Visual C++ Redistributables for Visual Studio 2019  
https://go.microsoft.com/fwlink/?LinkId=746572 &#8594; VC_redist.x64.exe  

Registry Explorer/RECmd v1.6.0.0 (2021-06-08)  
https://binaryforay.blogspot.com/  

ShellBags Explorer v1.4.0.0 (2021-05-24)  
https://binaryforay.blogspot.com/  

## Links
[MemProcFS](https://github.com/ufrisk/MemProcFS)  
[Demo of MemProcFS with Elasticsearch](https://www.youtube.com/watch?v=JcIlowlrvyI)  
[Sponsor MemProcFS project](https://github.com/sponsors/ufrisk)  
[MemProcFSHunter](https://github.com/memprocfshunt/MemProcFSHunter)  
