# MemProcFS-Analyzer
MemProcFS-Analyzer.ps1 is a PowerShell script utilized to simplify the usage of MemProcFS and to assist with the analysis workflow.

MemProcFS - The Memory Process File System by Ulf Frisk  
https://github.com/ufrisk/MemProcFS  

Features:
* Auto-Install of MemProcFS, EvtxECmd, Elasticsearch, Kibana  
* Auto-Update of MemProcFS, EvtxECmd (incl. Maps), Elasticsearch, Kibana, ClamAV Virus Databases (CVD)  
* Update-Info when there's a new version of ClamAV or a new Redistributable packaged Dokany Library Bundle available  
* Multi-Threaded scan w/ ClamAV for Windows  
* Extracting IPv4/IPv6 
* IP2ASN Mapping w/ [Team Cymru](https://team-cymru.com/community-services/ip-asn-mapping/)  
* Checking for Unusual Parent-Child Relationships  
* Extracting Windows Event Log Files and processing w/ EvtxECmd &#8594; Timeline Explorer ([EZTools](https://ericzimmerman.github.io/) by Eric Zimmerman)  
* Collecting Evidence Files (Secure Archive Container &#8594; PW: MemProcFS)  

## Download 
Download the latest version of **MemProcFS-Analyzer** from the [Releases](https://github.com/evild3ad/MemProcFS-Analyzer/releases) section.  

## Usage  
Launch Windows PowerShell ISE or Visual Studio Code (PSVersion: 5.1) as Administrator and open/run MemProcFS-Analyzer.ps1. 

![File-Browser](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/File-Browser.png)  
**Fig 1:** Select your Raw Physical Memory Dump

![Auto-Install](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/Auto-Install.png)  
**Fig 2:** MemProcFS-Analyzer checks for dependencies (First Run)

![Microsoft-Internet-Symbol-Store](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/Microsoft-Internet-Symbol-Store.png)  
**Fig 3:** Accept Terms of Use (First Run)

![ClamAV-Scan](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/ClamAV-Scan.png)  
**Fig 4:** Multi-Threaded ClamAV Scan

![Elasticsearch](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/Elasticsearch.png)  
**Fig 5:** Processing Windows Event Logs (EVTX)

![ELK-Import](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/ELK-Import.png)  
**Fig 6:** ELK Import

![ELK-Timeline](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/ELK-Timeline.png)  
**Fig 7:** Happy ELK Hunting!

![Secure-Archive-Container](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/Secure-Archive-Container.png)  
**Fig 8:** ClamAV Scan found 29 infected file(s)

![Message-Box](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/Message-Box.png)  
**Fig 8:** Press **OK** to shutdown MemProcFS and Elastisearch/Kibana

![Output](https://github.com/evild3ad/MemProcFS-Analyzer/blob/d3bfab5168ed22979338e4a379200020885cdc82/Screenshots/Output.png)  
**Fig 10:** Secure Archive Container (PW: MemProcFS)

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

4. Done! :smiley:  

## Dependencies
7-Zip 9.20 Command Line Version (2010-11-18)  
https://www.7-zip.org/download.html  

ClamAV - Windows Packages &#8594; Win64 &#8594; ClamAV-0.103.2.exe (2021-04-07)  
https://www.clamav.net/downloads  
https://www.clamav.net/documents/installing-clamav-on-windows &#8594; First Time Set-Up  

Dokany Library Bundle v1.4.0.1000 x64 (2020-06-01)  
https://github.com/dokan-dev/dokany/releases/latest &#8594; DokanSetup_redist.exe  

Elasticsearch 7.12.1 (2021-04-27)  
https://www.elastic.co/downloads/elasticsearch  

EvtxECmd v0.6.5.0 (2020-12-21)  
https://binaryforay.blogspot.com/  

MemProcFS v3.10 - The Memory Process File System (2021-04-26)  
https://github.com/ufrisk/MemProcFS  

Microsoft Visual C++ Redistributables for Visual Studio 2019
https://go.microsoft.com/fwlink/?LinkId=746572 &#8594; VC_redist.x64.exe  

Netcat v1.11 (2009-04-10)  
https://joncraton.org/blog/46/netcat-for-windows/  

## Links
[MemProcFS](https://github.com/ufrisk/MemProcFS)  
[Demo of MemProcFS with Elasticsearch](https://www.youtube.com/watch?v=JcIlowlrvyI)  
[Sponsor MemProcFS project](https://github.com/sponsors/ufrisk)  
[MemProcFSHunter](https://github.com/memprocfshunt/MemProcFSHunter)  
