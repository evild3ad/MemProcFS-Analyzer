Description: Kroll RECmd Batch File
Author: Andrew Rathbun
Version: 1.22
Id: ecc582d5-a1b1-4256-ae64-ca2263b8f971
Keys:
#
# Kroll_Batch README: https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.md
#  => Add changelog in this readme after additions.
#
# --------------------
# TABLE OF CONTENTS
# --------------------
#
# System Info
# Devices
# Network Shares
# User Accounts
# Program Execution
# User Activity
# Autoruns
# Third Party Applications
# Cloud Storage
# Services
# Event Logs
# Microsoft Office/Office 365
# Microsoft Exchange
# Web Browsers
# Installed Software
# Volume Shadow Copies
# Threat Hunting
#
# --------------------
# SYSTEM INFO
# --------------------

# System Info -> Basic System Info

    -
        Description: WinLogon
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\WinLogon
        ValueName: LastUsedUsername
        Recursive: false
        Comment: "Displays the username of the last user logged in to this system"

# https://windowsir.blogspot.com/2013/04/plugin-winlogon.html

    -
        Description: WinLogon
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\WinLogon
        ValueName: AutoLogonSID
        Recursive: false
        Comment: "Displays the SID of the user who is set to auto login to Windows"

# https://windowsir.blogspot.com/2013/04/plugin-winlogon.html

    -
        Description: WinLogon
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\WinLogon
        ValueName: AutoAdminLogon
        Recursive: false
        Comment: "Displays whether the system will automatically login a user as Admin, 0 = Disabled, 1 = Enabled"
    -
        Description: WinLogon
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\WinLogon
        ValueName: DefaultUserName
        Recursive: false
        Comment: "Displays the default username the system will log in as"
    -
        Description: WinLogon
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\WinLogon
        ValueName: DefaultPassword
        Recursive: false
        Comment: "Displays the password to be used for the account specified in DefaultUserName"
    -
        Description: LogonUI
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\LogonUI
        ValueName: LastLoggedOnUser
        Recursive: false
        Comment: "Displays the last logged on SAM user"
    -
        Description: LogonUI
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\LogonUI
        ValueName: LastLoggedOnSAMUser
        Recursive: false
        Comment: "Displays the last logged on user"
    -
        Description: LogonUI
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\LogonUI
        ValueName: LastLoggedOnDisplayName
        Recursive: false
        Comment: "Displays the last logged on user's display name"
    -
        Description: LogonUI
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\LogonUI
        ValueName: SelectedUserSID
        Recursive: false
        Comment: "Displays the selected user's SID"
    -
        Description: LogonUI
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\LogonUI
        ValueName: LastLoggedOnUserSID
        Recursive: false
        Comment: "Displays the last logged on user's SID"
    -
        Description: Windows Boot Volume
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup
        ValueName: SystemPartition
        Recursive: false
        Comment: "Identifies the system volume where Windows booted from"

# https://www.microsoftpressstore.com/articles/article.aspx?p=2201310
# https://stackoverflow.com/questions/15361617/retrieve-the-partition-number-of-bootmgr-on-windows-vista-and-later

    -
        Description: ControlSet Configuration
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Select
        ValueName: Current
        Recursive: false
        Comment: "Displays value for the current ControlSet"

# https://what-when-how.com/windows-forensic-analysis/registry-analysis-windows-forensic-analysis-part-3/
# https://msirevolution.wordpress.com/2012/03/31/what-is-currentcontrolset001-in-windows-registry/

    -
        Description: ControlSet Configuration
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Select
        ValueName: Default
        Recursive: false
        Comment: "Displays value for the default ControlSet"

# https://what-when-how.com/windows-forensic-analysis/registry-analysis-windows-forensic-analysis-part-3/
# https://msirevolution.wordpress.com/2012/03/31/what-is-currentcontrolset001-in-windows-registry/

    -
        Description: ControlSet Configuration
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Select
        ValueName: Failed
        Recursive: false
        Comment: "Displays value for the ControlSet that was unable to boot Windows successfully"

# https://what-when-how.com/windows-forensic-analysis/registry-analysis-windows-forensic-analysis-part-3/
# https://msirevolution.wordpress.com/2012/03/31/what-is-currentcontrolset001-in-windows-registry/

    -
        Description: ControlSet Configuration
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Select
        ValueName: LastKnownGood
        Recursive: false
        Comment: "Displays value for the last known good ControlSet"

# https://what-when-how.com/windows-forensic-analysis/registry-analysis-windows-forensic-analysis-part-3/
# https://msirevolution.wordpress.com/2012/03/31/what-is-currentcontrolset001-in-windows-registry/

    -
        Description: Shutdown Time
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet00*\Control\Windows
        ValueName: ShutdownTime
        Recursive: false
        IncludeBinary: true
        BinaryConvert: FILETIME
        Comment: "Last system shutdown time"

# https://www.winhelponline.com/blog/how-to-determine-the-last-shutdown-date-and-time-in-windows/

    -
        Description: Windows OS Language
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\Nls\Language
        ValueName: InstallLanguage
        Recursive: false
        Comment: "Default OS Language, 0409 is English"

# https://serverfault.com/questions/957167/windows-10-1809-region-language-registry-keys
# https://www.itprotoday.com/windows-78/where-registry-language-setting-each-user-stored

    -
        Description: Virtual Memory Pagefile Encryption Status
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\FileSystem
        ValueName: NtfsEncryptPagingFile
        Recursive: false
        Comment: "Virtual Memory Pagefile Encryption, 0 = Disabled, 1 = Enabled"

# https://www.tenforums.com/tutorials/77782-enable-disable-virtual-memory-pagefile-encryption-windows-10-a.html

    -
        Description: TRIM Status
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\FileSystem
        ValueName: DisableDeleteNotification
        Recursive: false
        Comment: "TRIM, 0 = Enabled, 1 = Disabled"

# https://www.howtogeek.com/257196/how-to-check-if-trim-is-enabled-for-your-ssd-and-enable-it-if-it-isnt/

    -
        Description: NTFS File Compression Status
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\FileSystem
        ValueName: NtfsDisableCompression
        Recursive: false
        Comment: "NTFS File Compression, 0 = Enabled, 1 = Disabled"

# https://thegeekpage.com/enable-disable-ntfs-compression-windows-improve-performance/
# https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior

    -
        Description: NTFS File Encryption Status
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\FileSystem
        ValueName: NtfsDisableEncryption
        Recursive: false
        Comment: "NTFS File Encryption, 0 = Enabled, 1 = Disabled"

# https://www.tenforums.com/tutorials/97782-enable-disable-ntfs-file-encryption-windows.html
# https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior

    -
        Description: NTFS LastAccess Timestamp Status
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\FileSystem
        ValueName: NtfsDisableLastAccessUpdate
        Recursive: false
        Comment: "NTFS LastAccess Timestamp, 2147483650 = Enabled, 1 = Disabled"

# https://dfir.ru/2018/12/08/the-last-access-updates-are-almost-back/
# https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior

    -
        Description: Long Paths Enabled
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\FileSystem
        ValueName: LongPathsEnabled
        Recursive: false
        Comment: "NTFS Long Paths, 0 = Disabled, 1 = Enabled"

# https://www.howtogeek.com/266621/how-to-make-windows-10-accept-file-paths-over-260-characters/

    -
        Description: Prefetch Status
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet00*\Control\Session Manager\Memory Management\PrefetchParameters
        ValueName: EnablePrefetcher
        Recursive: false
        Comment: "0 = Disabled, 1 = Application Prefetching Enabled, 2 = Boot Prefetching Enabled, 3 = Application and Boot Prefetching Enabled"

# https://www.thewindowsclub.com/disable-superfetch-prefetch-ssd
# https://youtu.be/f4RAtR_3zcs
# https://resources.infosecinstitute.com/topic/windows-systems-artifacts-digital-forensics-part-iii-prefetch-files/
# https://www.hackingarticles.in/forensic-investigation-prefetch-file/
# https://countuponsecurity.com/2016/05/16/digital-forensics-prefetch-artifacts/
# https://or10nlabs.tech/prefetch-forensics/

    -
        Description: Clear Page File at Shutdown Status
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet00*\Control\Session Manager\Memory Management
        ValueName: ClearPageFileAtShutdown
        Recursive: false
        Comment: "0 = Disabled, 1 = Enabled"

# https://tweaks.com/windows/37350/clear-pagefile-111n-shutdown/
# https://www.majorgeeks.com/content/page/clear_page_file.html
# https://docs.microsoft.com/en-us/windows/client-management/introduction-page-file

    -
        Description: System Time Zone Information
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet00*\Control\TimeZoneInformation
        Recursive: false
        Comment: "Displays the current Time Zone configuration for this system"

# TimeZoneInfo plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.TimeZoneInformation

# https://kb.digital-detective.net/display/BF/Identification+of+Time+Zone+Settings+on+Suspect+Computer

    -
        Description: Network Connections
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList
        Recursive: false
        Comment: "Displays list of network connections"

# KnownNetworks plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.KnownNetworks
# https://www.forensafe.com/blogs/wirelessnetworks.html

    -
        Description: Device Classes
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\DeviceClasses
        Recursive: false
        Comment: "Displays a list of PnP devices (Plug and Play) that were connected to this system"

# DeviceClasses plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.DeviceClasses
# https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-specific-registry-settings
# https://www.hecfblog.com/2013/08/daily-blog-67-understanding-artifacts.html

# System Info -> System Info (Current)

    -
        Description: System Info (Current)
        HiveType: NTUSER
        Category: System Info
        KeyPath: Software\Microsoft\Windows Media\WMSDK\General
        ValueName: ComputerName
        Recursive: false
        Comment: "Name of computer used by the user"
    -
        Description: System Info (Current)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet00*\Control\ComputerName\ComputerName
        ValueName: ComputerName
        Recursive: false
        Comment: "Name of computer used by the user"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: SystemRoot
        Recursive: false
        Comment: "Current location of %SystemRoot% Environment Variable"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: RegisteredOwner
        Recursive: false
        Comment: "Current registered owner"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: RegisteredOrganization
        Recursive: false
        Comment: "Current registered organization"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: DisplayVersion
        Recursive: false
        Comment: "Current milestone update version"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallTime
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: false
        Comment: "Current OS install time"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: ProductName
        Recursive: false
        Comment: "Current OS name"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallDate
        IncludeBinary: true
        BinaryConvert: EPOCH
        Recursive: false
        Comment: "Current OS install date"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallationType
        Recursive: false
        Comment: "Current OS installation type"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: EditionID
        Recursive: false
        Comment: "Current OS version and install info"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentMajorVersionNumber
        Recursive: false
        Comment: "Current OS version and install info"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentBuildNumber
        Recursive: false
        Comment: "Current OS version and install info"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentBuild
        Recursive: false
        Comment: "Current OS build information"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CompositionEditionID
        Recursive: false
        Comment: "Current OS license type"
    -
        Description: System Info (Current)
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: BuildLab
        Recursive: false
        Comment: "Current OS build information"

# System Info -> System Info (Historical)

    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: SystemRoot
        Recursive: false
        Comment: "Historical location of %SystemRoot% Environment Variable"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: RegisteredOwner
        Recursive: false
        Comment: "Historical registered owner"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: RegisteredOrganization
        Recursive: false
        Comment: "Historical registered organization"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: DisplayVersion
        Recursive: false
        Comment: "Historical milestone update version"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: InstallTime
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: false
        Comment: "Historical OS install time"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: ProductName
        Recursive: false
        Comment: "Historical OS name"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: InstallDate
        IncludeBinary: true
        BinaryConvert: EPOCH
        Recursive: false
        Comment: "Historical OS install date"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: InstallationType
        Recursive: false
        Comment: "Historical OS installation type"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: EditionID
        Recursive: false
        Comment: "Historical OS version and install info"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: CurrentMajorVersionNumber
        Recursive: false
        Comment: "Historical OS version and install info"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: CurrentBuildNumber
        Recursive: false
        Comment: "Historical OS version and install info"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: CurrentBuild
        Recursive: false
        Comment: "Historical OS build information"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: CompositionEditionID
        Recursive: false
        Comment: "Historical OS license type"
    -
        Description: System Info (Historical)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup\Source OS*
        ValueName: BuildLab
        Recursive: false
        Comment: "Historical OS build information"

# https://az4n6.blogspot.com/2017/02/when-windows-lies.html
# https://www.nextofwindows.com/when-was-my-windows-10-originally-installed

# System Info -> Network Configuration (IPv4)

# DHCPNetworkHints plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.DHCPNetworkHint
# Plugin not used currently

    -
        Description: Network Adapters
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}
        Recursive: false
        Comment: "Displays list of network adapters connected to this system"

# NetworkAdapters plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.NetworkAdapters

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: AddressType
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpConnForceBroadcastFlag
        Recursive: false
        Comment: "DHCP Broadcast, 0 = Disabled, 1 = Enabled"

# https://support.microsoft.com/en-us/topic/windows-vista-can-t-get-an-ip-address-from-certain-routers-or-dhcp-servers-ee61b030-e749-878b-9725-247d8bd95c5e

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpDefaultGateway
        Recursive: false
        Comment: "Displays the ordered list of gateways that can be used as the default gateway for this system."

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959606(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpDomain
        Recursive: false
        Comment: "Specifies the Domain Name System (DNS) domain name of the interface, as provided by the Dynamic Host Configuration Protocol (DHCP)"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962456(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpDomainSearchList
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpGatewayHardware
        IncludeBinary: true
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpGatewayHardwareCount
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpIPAddress
        Recursive: false
        Comment: "Specifies the IP addresses of the interface, as configured by Dynamic Host Configuration Protocol (DHCP)"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962469(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpNameServer
        Recursive: false
        Comment: "Stores a list of Domain Name System (DNS) servers to which Windows Sockets sends queries when it resolves names for the interface"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962470(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpServer
        Recursive: false
        Comment: "Stores the IP address of the Dynamic Host Configuration Protocol (DHCP) server that granted the lease to the IP address stored in the value of the DhcpIPAddress entry"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962473(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpSubnetMask
        Recursive: false
        Comment: "Specifies the subnet mask for the IP address specified in the value of either the IPAddress entry or the DhcpIPAddress entry"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962474(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpSubnetMaskOpt
        Recursive: false
        Comment: "Specifies the subnet mask associated with a Dynamic Host Configuration Protocol (DHCP) option"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962475(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: Domain
        Recursive: false
        Comment: "Specifies the Domain Name System (DNS) domain name of the interface, as provided by the Dynamic Host Configuration Protocol (DHCP)"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962476(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: EnableDHCP
        Recursive: false
        Comment: "DHCP status, 0 = Disabled, 1 = Enabled"

# https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mscs/enabledhcp

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: EnableMulticast
        Recursive: false
        Comment: "Multicast status, 0 = Disabled, 1 = Enabled"

# https://www.microsoftpressstore.com/articles/article.aspx?p=2217263&seqNum=8

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: IPAddress
        Recursive: false
        Comment: "Specifies the IP addresses of the interface"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc938245(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: IsServerNapAware
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: Lease
        Recursive: false
        Comment: "Specifies how long the lease on the IP address for this interface is valid"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978464(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: LeaseObtainedTime
        Recursive: false
        IncludeBinary: true
        BinaryConvert: EPOCH
        Comment: "Stores the time that the interface acquired the lease on its IP address"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978465(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: LeaseTerminatesTime
        Recursive: false
        IncludeBinary: true
        BinaryConvert: EPOCH
        Comment: "Stores the time when the lease on the interfaces' IP address expires"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978467(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: NameServer
        Recursive: false
        Comment: "Stores a list of Domain Name System (DNS) servers to which Windows Sockets sends queries when it resolves names for this interface"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978468(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: RegisterAdapterName
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: RegistrationEnabled
        Recursive: false
        Comment: "Dynamic DNS registration for a specific network interface controller (NIC)"

# https://www.serverbrain.org/networking-guide-2003/configuring-dynamic-dns-registration-problem.html

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: SubnetMask
        Recursive: false
        Comment: "Specifies the subnet mask for the IP address specified in the value of IPAddress or DhcpIPAddress"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc938248(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: T1
        Recursive: false
        Comment: "Displays time that the DHCP client stores for when the service will try to renew its IP address lease"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978470(v=technet.10)

    -
        Description: Network Configuration (IPv4)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: T2
        Recursive: false
        Comment: "Displays time that the DHCP client stores for when the service will try to broadcast a renewal request"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978471(v=technet.10)?redirectedfrom=MSDN

# System Info - Network Configuration (IPv6)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: AddressType
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpConnForceBroadcastFlag
        Recursive: false
        Comment: "DHCP Broadcast, 0 = Disabled, 1 = Enabled"

# https://support.microsoft.com/en-us/topic/windows-vista-can-t-get-an-ip-address-from-certain-routers-or-dhcp-servers-ee61b030-e749-878b-9725-247d8bd95c5e

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpDefaultGateway
        Recursive: false
        Comment: "Displays the ordered list of gateways that can be used as the default gateway for this system."

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959606(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpDomain
        Recursive: false
        Comment: "Specifies the Domain Name System (DNS) domain name of the interface, as provided by the Dynamic Host Configuration Protocol (DHCP)"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962456(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpDomainSearchList
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpGatewayHardware
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpGatewayHardwareCount
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpIPAddress
        Recursive: false
        Comment: "Specifies the IP addresses of the interface, as configured by Dynamic Host Configuration Protocol (DHCP)"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962469(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpNameServer
        Recursive: false
        Comment: "Stores a list of Domain Name System (DNS) servers to which Windows Sockets sends queries when it resolves names for the interface"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962470(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpServer
        Recursive: false
        Comment: "Stores the IP address of the Dynamic Host Configuration Protocol (DHCP) server that granted the lease to the IP address stored in the value of the DhcpIPAddress entry"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962473(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpSubnetMask
        Recursive: false
        Comment: "Specifies the subnet mask for the IP address specified in the value of either the IPAddress entry or the DhcpIPAddress entry"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962474(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: DhcpSubnetMaskOpt
        Recursive: false
        Comment: "Specifies the subnet mask associated with a Dynamic Host Configuration Protocol (DHCP) option"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962475(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: Domain
        Recursive: false
        Comment: "Specifies the Domain Name System (DNS) domain name of the interface, as provided by the Dynamic Host Configuration Protocol (DHCP)"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc962476(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: EnableDHCP
        Recursive: false
        Comment: "DHCP status, 0 = Disabled, 1 = Enabled"

# https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mscs/enabledhcp

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: EnableMulticast
        Recursive: false
        Comment: "Multicast status, 0 = Disabled, 1 = Enabled"

# https://www.microsoftpressstore.com/articles/article.aspx?p=2217263&seqNum=8

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: IPAddress
        Recursive: false
        Comment: "Specifies the IP addresses of the interface"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc938245(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: IsServerNapAware
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: Lease
        Recursive: false
        Comment: "Specifies how long the lease on the IP address for this interface is valid"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978464(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: LeaseObtainedTime
        Recursive: false
        IncludeBinary: true
        BinaryConvert: EPOCH
        Comment: "Stores the time that the interface acquired the lease on its IP address"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978465(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: LeaseTerminatesTime
        Recursive: false
        IncludeBinary: true
        BinaryConvert: EPOCH
        Comment: "Stores the time when the lease on the interfaces' IP address expires"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978467(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: NameServer
        Recursive: false
        Comment: "Stores a list of Domain Name System (DNS) servers to which Windows Sockets sends queries when it resolves names for this interface"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978468(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: RegisterAdapterName
        Recursive: false
        Comment: ""
    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: RegistrationEnabled
        Recursive: false
        Comment: "Dynamic DNS registration for a specific network interface controller (NIC)"

# https://www.serverbrain.org/networking-guide-2003/configuring-dynamic-dns-registration-problem.html

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: SubnetMask
        Recursive: false
        Comment: "Specifies the subnet mask for the IP address specified in the value of IPAddress or DhcpIPAddress"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc938248(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: T1
        Recursive: false
        Comment: "Displays time that the DHCP client stores for when the service will try to renew its IP address lease"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978470(v=technet.10)

    -
        Description: Network Configuration (IPv6)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        ValueName: T2
        Recursive: false
        Comment: "Displays time that the DHCP client stores for when the service will try to broadcast a renewal request"

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978471(v=technet.10)?redirectedfrom=MSDN

    -
        Description: Windows 10 Timeline Status
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: EnableActivityFeed
        Recursive: false
        Comment: "Windows 10 Activity Timeline status, 0 = Disabled, 1 = Enabled"

# https://www.majorgeeks.com/content/page/how_to_disable_or_enable_timeline_in_windows_10.html

    -
        Description: Windows 10 Timeline Status
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\PolicyManager\default\Privacy\EnableActivityFeed
        ValueName: value
        Recursive: false
        Comment: "Windows 10 Activity Timeline status, 0 = Disabled, 1 = Enabled"

# The above location is where this value exists on my personal machine. Adding it in case the other one doesn't get a hit.

    -
        Description: Clipboard History Status
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\PolicyManager\default\Privacy
        ValueName: EnableClipboardHistory
        Recursive: False
        Comment: "Displays the status of Clipboard History, 0 = Disabled, 1 = Enabled"

# The above location is where this value exists on my personal machine. Adding it in case the other one doesn't get a hit.

    -
        Description: Clipboard History Status
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Software\Policies\Microsoft\Windows\System
        ValueName: AllowCrossDeviceClipboard
        Recursive: False
        Comment: "Displays the status of Clipboard Sync Across Devices, 0 = Disabled, 1 = Enabled"

# https://www.tenforums.com/tutorials/110048-enable-disable-clipboard-sync-across-devices-windows-10-a.html

    -
        Description: Clipboard History Status
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\PolicyManager\default\Privacy\AllowCrossDeviceClipboard
        ValueName: value
        Recursive: False
        Comment: "Displays the status of Clipboard Sync Across Devices, 0 = Disabled, 1 = Enabled"

# The above location is where this value exists on my personal machine. Adding it in case the other one doesn't get a hit.

# System Info - SUM Database\User Access Logging

    -
        Description: User Access Logging (SUM DB)
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\WMI\Autologger\SUM
        ValueName: PollingInterval
        Recursive: False
        Comment: "Displays the updating interval for the SUM DB. Default is 24 hours. 60000 = 60 seconds, for example"

# https://youtu.be/p4XI8-ldE5o?t=627

# System Info - Firewall Rules

    -
        Description: Firewall Rules
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
        Recursive: False
        Comment: "Displays firewall rules on this system"

# FirewallRules plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.FirewallRules

    -
        Description: MAC Addresses
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet00*\Control\NetworkSetup2
        Recursive: False
        Comment: "Displays MAC Addresses related to this system"

# NetworkSetup2 plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.NetworkSetup2
# https://thinkdfir.com/2019/10/05/hunting-for-mac-addresses

# --------------------
# DEVICES
# --------------------

    -
        Description: Microphone
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone
        ValueName: LastUsedTimeStart
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: true
        Comment: "Displays the timestamp of when a microphone started being used with a given application"
    -
        Description: Microphone
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone
        ValueName: LastUsedTimeStop
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: true
        Comment: "Displays the timestamp of when a microphone stopped being used with a given application"
    -
        Description: Webcam
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\*\*
        ValueName: LastUsedTimeStart
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: true
        Comment: "Displays the timestamp of when a webcam started being used with a given application"
    -
        Description: Webcam
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\*\*
        ValueName: LastUsedTimeStop
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: true
        Comment: "Displays the timestamp of when a webcam stopped being used with a given application"
    -
        Description: Bluetooth Devices
        HiveType: SYSTEM
        Category: Devices
        KeyPath: ControlSet*\Services\BTHPORT\Parameters\Devices
        Recursive: false
        Comment: "Displays the Bluetooth devices that have been connected to this computer"

# BTHPORT plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.BluetoothServicesBthPort

    -
        Description: Volume Info Cache
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows Search\VolumeInfoCache
        Recursive: false
        Comment: "2 = Removable, 3 = Fixed, 4 = Network, 5 = Optical, 6 = RAM disk, 0 = Unknown"

# VolumeInfoCache plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.VolumeInfoCache
# https://docs.microsoft.com/en-us/dotnet/api/system.io.drivetype?view=net-5.0

# Devices -> USBSTOR

    -
        Description: USBSTOR
        HiveType: SYSTEM
        Category: Devices
        KeyPath: ControlSet*\Enum\USBSTOR
        Recursive: false
        Comment: "Displays list of USB devices that have been plugged into this system. If & is second character within serial number, serial number is only unique on the system"

# USBSTOR plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.USBSTOR
# https://www.jaiminton.com/cheatsheet/DFIR/#usb-information-1
# https://www.13cubed.com/downloads/dfir_cheat_sheet.pdf
# https://www.swiftforensics.com/2013/11/windows-8-new-registry-artifacts-part-1.html
# https://www.tristiansforensicsecurity.com/2018/11/28/basic-usb-forensics-in-windows/

    -
        Description: USB
        HiveType: SYSTEM
        Category: Devices
        KeyPath: ControlSet*\Enum\USB
        Recursive: false
        Comment: "Provides VID and PID numbers of USB devices. Match serial number from USBSTOR and search for VID and PID across the system"

# USB plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.USB
# https://www.tristiansforensicsecurity.com/2018/11/28/basic-usb-forensics-in-windows/

    -
        Description: MountPoints2
        HiveType: NTUSER
        Category: Devices
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
        Recursive: true
        Comment: "Mount Points - NTUSER"

# https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download
# https://eforensicsmag.com/investigating-usb-drives-using-mount-points-not-drive-letters-by-ali-hadi/
# https://www.andreafortuna.org/2017/10/18/windows-registry-in-forensic-analysis/
# https://www.forensicfocus.com/articles/forensic-analysis-of-the-windows-registry/

    -
        Description: Mounted Devices
        HiveType: SYSTEM
        Category: Devices
        KeyPath: MountedDevices
        Recursive: false
        Comment: "Last Write Timestamp is for entire key, not each individual value"

# MountedDevices plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryExplorer.MountedDevices
# https://what-when-how.com/windows-forensic-analysis/registry-analysis-windows-forensic-analysis-part-6/
# https://hatsoffsecurity.com/2014/12/04/mounted-devices-key/
# https://www.forensicfocus.com/articles/forensic-analysis-of-the-windows-registry/
# https://www.andreafortuna.org/2017/10/18/windows-registry-in-forensic-analysis/
# https://www.binary-zone.com/2020/04/03/no-drive-letter-no-usb-think-again/
# https://windowsir.blogspot.com/2004/12/mounted-devices.html

    -
        Description: Windows Portable Devices
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows Portable Devices
        Recursive: false
        Comment: "Displays list of USB devices previously connected to this system"

# WindowsPortableDevices plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.WindowsPortableDevices
# https://df-stream.com/2017/10/amcache-and-usb-device-tracking/

    -
        Description: SCSI
        HiveType: SYSTEM
        Category: Devices
        KeyPath: ControlSet*\Enum\SCSI
        Recursive: false
        Comment: "Displays a list of SCSI devices connected to this system"

# SCSI plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.SCSI

# --------------------
# NETWORK SHARES
# --------------------

# Network Shares -> Network Shares
    -
        Description: Network Shares
        HiveType: NTUSER
        Category: Network Shares
        KeyPath: Network
        ValueName: RemotePath
        Recursive: true
        Comment: "Displays the UNC path for a mounted network share"
    -
        Description: Network Shares
        HiveType: NTUSER
        Category: Network Shares
        KeyPath: Network
        ValueName: UserName
        Recursive: true
        Comment: "Displays the user account associated with the mounted network share"
    -
        Description: Network Shares
        HiveType: NTUSER
        Category: Network Shares
        KeyPath: Network
        ValueName: ProviderName
        Recursive: true
        Comment: "Displays the provider of the mounted network share"

# https://social.technet.microsoft.com/Forums/ie/en-US/65eb8a2f-988f-40a7-b6ff-616a050c8efc/list-all-mapped-drives-for-all-users-that-have-logged-into-a-computer?forum=ITCG

    -
        Description: Network Drive MRU
        HiveType: NTUSER
        Category: Network Shares
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
        Recursive: false
        Comment: "Displays drives that were mapped by the user"

# https://community.spiceworks.com/topic/137045-remove-previously-mapped-network-drive-paths
# https://answers.microsoft.com/en-us/windows/forum/windows_7-networking/cleanup-network-drives-list/1247aca3-deb6-493d-b937-24b40087cbc7?auth=1

    -
        Description: Network Shares
        HiveType: SYSTEM
        Category: Network Shares
        KeyPath: ControlSet00*\Services\LanmanServer\Shares
        Recursive: true
        Comment: "Displays the share names and permissions of network shares"

# https://www.coretechnologies.com/blog/windows-services/lanmanserver/
# https://docs.microsoft.com/en-us/troubleshoot/windows-client/networking/saving-restoring-existing-windows-shares

# --------------------
# USER ACCOUNTS
# --------------------

    -
        Description: User Accounts (SAM)
        HiveType: SAM
        Category: User Accounts
        KeyPath: SAM\Domains\Account\Users
        Recursive: false
        Comment: "User accounts in SAM hive"

# SAM plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.SAM
# https://www.forensafe.com/blogs/useraccounts.html

    -
        Description: User Accounts (SOFTWARE)
        HiveType: SOFTWARE
        Category: User Accounts
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList
        Recursive: false
        Comment: "User accounts in SOFTWARE hive"

# ProfileList plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.ProfileList
# https://content-calpoly-edu.s3.amazonaws.com/cci/1/documents/ccic_forensics_manual/CCIC%20Chapter%204%20-%20Understanding%20the%20Registry.pdf

    -
        Description: User Accounts (SECURITY)
        HiveType: SECURITY
        Category: User Accounts
        KeyPath: Policy\Accounts\*
        IncludeBinary: true
        Recursive: false
        Comment: "Built-in accounts in SECURITY hive"

# https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows

    -
        Description: Built-in User Accounts (SAM)
        HiveType: SAM
        Category: User Accounts
        KeyPath: SAM\Domains\Builtin\Aliases
        Recursive: false
        Comment: "Built-in accounts in SAM hive"

# SAMBuiltIn plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.SAMBuiltin
# https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts

# --------------------
# PROGRAM EXECUTION
# --------------------

# Porgram Execution -> Windows Sysinternals

    -
        Description: Sysinternals
        HiveType: NTUSER
        Category: Installed Software
        KeyPath: SOFTWARE\Sysinternals\*
        ValueName: EulaAccepted
        Recursive: false
        Comment: "Displays all SysInternals Tools that had the EULA accepted, indicating either execution of the tool or the Registry values were added intentionally prior to execution"

# https://docs.microsoft.com/en-us/sysinternals/
# https://hahndorf.eu/blog/post/2010/03/07/WorkAroundSysinternalsLicensePopups
# https://twitter.com/JohnLaTwC/status/1414207856220463105

    -
        Description: JumplistData
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Search\JumplistData
        Recursive: false
        Comment: "Displays last execution time of a program"

# JumplistData plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.JumplistData
# https://twitter.com/sv2hui/status/1005763370186891269?lang=en

    -
        Description: RecentApps
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
        Recursive: true
        Comment: "RecentApps"

# RecentApps plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.RecentApps

    -
        Description: RunMRU
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        Recursive: false
        Comment: "Tracks commands from the Run box in the Start menu, lower MRU # (Value Data3) = more recent"

# RunMRU plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.RunMRU
# https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/
# https://www.andreafortuna.org/2017/10/18/windows-registry-in-forensic-analysis/
# https://silo.tips/download/a-forensic-analysis-of-the-windows-registry
# https://www.forensafe.com/blogs/runmru.html

    -
        Description: AppCompatCache
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet00*\Control\Session Manager\AppCompatCache
        ValueName: AppCompatCache
        Recursive: false
        Comment: "AKA ShimCache, data is only written to this value at reboot by winlogon.exe"

# AppCompatCache plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.AppCompatCache
# https://medium.com/@bromiley/windows-wednesday-shim-cache-1997ba8b13e7
# https://www.youtube.com/watch?v=ZKlyu-HOvxY
# https://www.fireeye.com/blog/threat-research/2015/06/caching_out_the_val.html
# https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
# https://www.sans.org/blog/mass-triage-part-4-processing-returned-files-appcache-shimcache/
# https://countuponsecurity.com/tag/shimcache/
# https://techcommunity.microsoft.com/t5/ask-the-performance-team/demystifying-shims-or-using-the-app-compat-toolkit-to-make-your/ba-p/374947

    -
        Description: AppCompatFlags
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
        Recursive: false
        Comment: "Displays programs that are configured to run in Compatibility Mode in Windows"

# AppCompatFlags2 plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.AppCompatFlags2
# https://journeyintoir.blogspot.com/2013/12/revealing-program-compatibility.html

    -
        Description: CIDSizeMRU
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU
        Recursive: false
        Comment: "Recently ran applications, lower MRU # (Value Data3) = more recent"

# CIDSizeMRU plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.CIDSizeMRU
# https://windowsir.blogspot.com/2013/07/howto-determine-user-access-to-files.html
# https://windowsir.blogspot.com/2013/07/howto-determine-program-execution.html

# Program Execution -> BAM/DAM

    -
        Description: Background Activity Moderator (BAM)
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet*\Services\BAM\State\UserSettings\*
        Recursive: false
        Comment: "Displays the last execution time of a program"

# Bam plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Bam
# https://www.andreafortuna.org/2018/05/23/forensic-artifacts-evidences-of-program-execution-on-windows-systems/
# https://www.cellebrite.com/en/analyzing-program-execution-windows-artifacts/
# https://www.linkedin.com/pulse/alternative-prefetch-bam-costas-katsavounidis/

    -
        Description: Desktop Activity Moderator (DAM)
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet*\Services\DAM\State\UserSettings\*
        Recursive: false
        Comment: "DAM"

# Bam plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Bam
# https://www.cellebrite.com/en/analyzing-program-execution-windows-artifacts/

    -
        Description: Regedit.exe Last Run
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Applets\Regedit
        Recursive: false
        Comment: "Displays the last key opened with RegEdit"

# https://www.thewindowsclub.com/jump-to-any-registry-key-windows
# https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Software/Microsoft/Windows/CurrentVersion/Applets/Regedit/index

    -
        Description: UserAssist
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count
        Recursive: false
        Comment: "GUI-based programs launched from the desktop"

# UserAssist plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.UserAssist
# https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download
# https://blog.didierstevens.com/programs/userassist/
# https://www.andreafortuna.org/2018/05/23/forensic-artifacts-evidences-of-program-execution-on-windows-systems/
# https://countuponsecurity.com/tag/userassist/
# https://www.cellebrite.com/en/analyzing-program-execution-windows-artifacts/

    -
        Description: MuiCache (Vista+)
        HiveType: UsrClass
        Category: Program Execution
        KeyPath: Local Settings\Software\Microsoft\Windows\Shell\MuiCache
        Recursive: false
        Comment: "Displays new applications that have been executed within Windows"

# https://www.nirsoft.net/utils/muicache_view.html
# https://windowsir.blogspot.com/2005/12/mystery-of-muicachesolved.html
# https://www.fireeye.com/blog/threat-research/2013/08/execute.html

    -
        Description: MuiCache (2000/XP/2003)
        HiveType: UsrClass
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\ShellNoRoam\MUICache
        Recursive: false
        Comment: "Displays new applications that have been executed within Windows"

# https://www.nirsoft.net/utils/muicache_view.html
# https://windowsir.blogspot.com/2005/12/mystery-of-muicachesolved.html
# https://www.fireeye.com/blog/threat-research/2013/08/execute.html

    -
        Description: RADAR
        HiveType: SOFTWARE
        Category: Program Execution
        KeyPath: Microsoft\RADAR\HeapLeakDetection
        Recursive: false
        Comment: "Displays applications that were running at one point in time on this system"

# RADAR plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.RADAR
# http://windowsir.blogspot.com/2011/09/registry-stuff.html
# https://harelsegev.github.io/posts/the-mystery-of-the-heapleakdetection-registry-key/

# --------------------
# USER ACTIVITY
# --------------------

    -
        Description: Pinned Taskbar Items
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\TaskBand
        ValueName: Favorites
        Recursive: false
        Comment: "Displays pinned Taskbar items"

# TaskBand plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Taskband
# https://tzworks.net/prototype_page.php?proto_id=19

    -
        Description: TypedPaths
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
        Recursive: false
        Comment: "Displays paths that were typed by the user in Windows Explorer"

# https://www.hecfblog.com/2018/09/daily-blog-483-typed-paths-amnesia.html
# http://windowsir.blogspot.com/2013/07/howto-determine-user-access-to-files.html
# https://www.forensafe.com/blogs/typedpaths.html

    -
        Description: TypedURLs
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Internet Explorer\TypedURLs
        Recursive: false
        Comment: "Internet Explorer/Edge Typed URLs"

# TypedURLs plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.TypedURLs
# https://crucialsecurity.wordpress.com/2011/03/14/typedurls-part-1/
# https://www.andreafortuna.org/2017/10/18/windows-registry-in-forensic-analysis/
# https://tzworks.net/prototype_page.php?proto_id=19
# https://www.forensafe.com/blogs/typedurls.html

    -
        Description: Microsoft Office MRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: SOFTWARE\Microsoft\Office\*\*\User MRU\*\File MRU
        Recursive: false
        Comment: "Microsoft Office Recent Files, lower Item value (Value Name) = more recent"

# OfficeMRU plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.OfficeMRU
# https://www.eshlomo.us/windows-forensics-analysis-evidence/
# https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download
# https://www.andreafortuna.org/2017/10/18/windows-registry-in-forensic-analysis/
# https://df-stream.com/category/microsoft-office-forensics/

    -
        Description: WordWheelQuery
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
        Recursive: true
        Comment: "User Searches"

# https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download
# https://tzworks.net/prototype_page.php?proto_id=19
# https://www.forensicfocus.com/forums/general/how-to-check-what-words-have-been-searched-in-computer/

    -
        Description: FirstFolder
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder
        Recursive: true
        Comment: "FirstFolder, tracks the application's first folder that is presented to the user during an Open or Save As operation"

# FirstFolder plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.FirstFolder
# https://research.ijcaonline.org/cognition2015/number4/cog2174.pdf
# https://www.sans.org/blog/opensavemru-and-lastvisitedmru/

    -
        Description: OpenSavePidlMRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
        Recursive: false
        Comment: "Tracks files that have been opened or saved within a Windows shell dialog box"

# OpenSavePidlMRU plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.OpenSavePidlMRU
# https://www.sans.org/blog/opensavemru-and-lastvisitedmru/

    -
        Description: OpenSaveMRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU
        Recursive: false
        Comment: "Tracks files that have been opened or saved within a Windows shell dialog box"

# OpenSaveMRU plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.OpenSaveMRU

    -
        Description: LastVisitedPidlMRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        Recursive: false
        Comment: "Tracks the specific executable used by an application to open the files documented in OpenSavePidlMRU"

# LastVisitedPidlMRU plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.LastVisitedPidlMRU
# https://www.sans.org/blog/opensavemru-and-lastvisitedmru
# https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/
# https://www.eshlomo.us/windows-forensics-analysis-evidence/
# https://lifars.com/wp-content/uploads/2020/05/NTUSER-Technical-Guide.pdf
# https://www.forensafe.com/blogs/opensavemru.html

    -
        Description: LastVisitedPidlMRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy
        Recursive: false
        Comment: "Tracks the specific executable used by an application to open the files documented in OpenSavePidlMRU"

# LastVisitedPidlMRU plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.LastVisitedPidlMRU
# https://www.sans.org/blog/opensavemru-and-lastvisitedmru
# https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/
# https://www.eshlomo.us/windows-forensics-analysis-evidence/
# https://lifars.com/wp-content/uploads/2020/05/NTUSER-Technical-Guide.pdf
# https://www.forensafe.com/blogs/opensavemru.html

    -
        Description: RecentDocs
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        Recursive: true
        Comment: "Files recently opened from Windows Explorer"

# RecentDocs plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.RecentDocs
# https://forensic4cast.com/2019/03/the-recentdocs-key-in-windows-10/
# https://www.andreafortuna.org/2017/10/18/windows-registry-in-forensic-analysis/
# https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/
# https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download
# https://www.forensafe.com/blogs/recentDocs.html

    -
        Description: Recent File List
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\*\*\Recent File List
        Recursive: false
        Comment: "Displays recent files accessed by the user with an application"

# https://www.forensafe.com/blogs/paintmru.html

    -
        Description: Recent Folder List
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\*\*\Recent Folder List
        Recursive: false
        Comment: ""
    -
        Description: Recent Document List
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\*\*\Settings\Recent Document List
        Recursive: false
        Comment: ""
    -
        Description: Recent
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\*\*\Recent
        Recursive: false
        Comment: ""
    -
        Description: RecentFind
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\*\*\RecentFind
        Recursive: false
        Comment: ""
    -
        Description: Recent File List
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\*\Recent File List
        Recursive: false
        Comment: ""
    -
        Description: User Shell Folders
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
        Recursive: false
        Comment: "Displays where a user's Shell folders are mapped to"

# User Activity -> FeatureUsage

# FeatureUsage plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.FeatureUsage
# Plugin not used simply because by parsing each value individually, helpful comments can be added. Using the plugin and not using the plugin still produces an identical number of rows for the CSV, in testing

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated
        Recursive: true
        Comment: "Displays the number of times the user has received a notification for an application"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch
        Recursive: true
        Comment: "Displays the number of times a pinned application was launched from the taskbar"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched
        Recursive: true
        Comment: "Displays the number of times an application switched focus (i.e. minimized, maximized, etc)"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView
        Recursive: true
        Comment: "Displays the number of times an application was right-clicked"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
        ValueName: StartButton
        Recursive: true
        Comment: "Displays the number of times the Start button was clicked"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
        ValueName: ClockButton
        Recursive: true
        Comment: "Displays the number of times the Clock button was clicked"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
        ValueName: MultitaskingButton
        Recursive: true
        Comment: "Displays the number of times the Multitasking button was clicked"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
        ValueName: NotificationCenterButton
        Recursive: true
        Comment: "Displays the number of times the Notification Center button was clicked"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
        ValueName: SearchButton
        Recursive: true
        Comment: "Displays the number of times the Search button was clicked"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
        ValueName: SearchBox
        Recursive: true
        Comment: "Displays the number of times the Search box was clicked"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
        ValueName: ShowDesktopButton
        Recursive: true
        Comment: "Displays the number of times the Show Desktop button was clicked"

# https://www.group-ib.com/blog/featureusage
# https://www.crowdstrike.com/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/

# User Activity -> Terminal Server Client (RDP)

    -
        Description: Terminal Server Client (RDP)
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Terminal Server Client
        Recursive: false
        Comment: "Displays the IP addresses/hostnames of devices this system has connected to (Outbound RDP)"

# TerminalServerClient plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.TerminalServerClient
# Default subkey stores previous RDP connection entries the user has connected to
# UsernameHint value stores the username used on remote machine during RDP session
# https://jpcertcc.github.io/ToolAnalysisResultSheet/details/mstsc.htm
# https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/remove-entries-from-remote-desktop-connection-computer
# https://www.cyberfox.blog/tag/rdp-mru/
# https://ir3e.com/chapter-14-other-applications/

# --------------------
# AUTORUNS
# --------------------

# https://www.microsoftpressstore.com/articles/article.aspx?p=2762082

    -
        Description: Run (Group Policy)
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment: "Group Policy Run Key"
    -
        Description: Run (NTUSER)
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: "Program execution upon successful user logon"

# https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
# https://www.andreafortuna.org/2017/10/18/windows-registry-in-forensic-analysis/

    -
        Description: RunOnce (NTUSER)
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: "Program execution upon successful user logon"

# https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys

    -
        Description: Run (SYSTEM)
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: "Program execution upon successful user logon"

# https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys

    -
        Description: RunOnce (SYSTEM)
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: "Program execution upon successful user logon"

# https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys

    -
        Description: RunNotification
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunNotification
        Recursive: false
        Comment: "New in Windows 11, compare with other more researched Autoruns artifacts"

# new in Windows 11, more research needed

# Autoruns -> Startup Programs (SOFTWARE\NTUSER)

    -
        Description: Startup Programs
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
        IncludeBinary: true
        Recursive: true
        Comment: "Displays list of programs that start up upon system boot"
    -
        Description: Startup Programs
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32
        IncludeBinary: true
        Recursive: true
        Comment: "Displays list of programs that start up upon system boot"
    -
        Description: Startup Programs
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder
        IncludeBinary: true
        Recursive: true
        Comment: "Displays list of programs that start up upon system boot"
    -
        Description: Startup Programs
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
        IncludeBinary: true
        Recursive: true
        Comment: "Displays list of programs that start up upon system boot"
    -
        Description: Startup Programs
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32
        IncludeBinary: true
        Recursive: true
        Comment: "Displays list of programs that start up upon system boot"
    -
        Description: Startup Programs
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder
        IncludeBinary: true
        Recursive: true
        Comment: "Displays list of programs that start up upon system boot"

# https://www.hexacorn.com/blog/2019/02/23/beyond-good-ol-run-key-part-104/

    -
        Description: Scheduled Tasks (TaskCache)
        HiveType: Software
        Category: Autoruns
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        Recursive: false
        Comment: "Displays Scheduled Tasks and their last start/stop time"

# TaskCache plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.TaskCache
# https://digital-forensics.sans.org/media/DFPS_FOR508_v4.4_1-19.pdf
# https://www.jaiminton.com/cheatsheet/DFIR/#t1060-registry-run-keys--startup-folder
# https://jpcertcc.github.io/ToolAnalysisResultSheet/details/schtasks.htm
# https://dfirtnt.wordpress.com/registry-persistence-paths/
# https://www.forensafe.com/blogs/taskscheduler.html

# --------------------
# THIRD PARTY APPLICATIONS
# --------------------

# Do not include anything in NTUSER or SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall as that is covered already by Installed Software entries
# Sometimes, there are values for third party applications not covered under the standard DisplayVersion, Publisher, InstallLocation, InstallDate, and DisplayName entries. I've seen Inno Setup: User, Inno Setup: Language, and Inno Setup: App Path
# For this section, please include a subheader and a URL, even if its only one entry per program

# Third Party Applications -> VNC Viewer - https://www.realvnc.com/en/connect/download/viewer/

    -
        Description: VNC Viewer
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\RealVNC\vncviewer
        Recursive: true
        Comment: "Displays artifactrs relating to VNC Viewer"

# Third Party Applications -> QNAP QFinder - https://www.qnap.com/en-us/utilities/essentials

    -
        Description: QNAP QFinder
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\QNAP\Qfinder\WOL\*
        ValueName: SvrName
        Recursive: false
        Comment: "Displays the name of the QNAP as it was assigned by the user"
    -
        Description: QNAP QFinder
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\QNAP\Qfinder\WOL\*
        ValueName: SvrIPAddr
        Recursive: false
        Comment: "Displays the IP Address of the QNAP as it was assigned by the user"
    -
        Description: QNAP QFinder
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\QNAP\Qfinder\WOL\*
        ValueName: SvrVersion
        Recursive: false
        Comment: "Displays the current firmware version of the QNAP"
    -
        Description: QNAP QFinder
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\QNAP\Qfinder\WOL\*
        ValueName: SvrType
        Recursive: false
        Comment: "Displays the type of the QNAP device"
    -
        Description: QNAP QFinder
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\QNAP\Qfinder\WOL\*
        ValueName: SvrModel
        Recursive: false
        Comment: "Displays the model of the QNAP device"
    -
        Description: QNAP QFinder
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\QNAP\Qfinder
        ValueName: InstallDate
        Recursive: false
        Comment: "Displays the install date of QNAP QFinder"

# Third Party Applications -> Total Commander - https://www.ghisler.com/

    -
        Description: Total Commander
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Ghisler\Total Commander
        Recursive: false
        Comment: "Total Commander Registry artifacts"
    -
        Description: Total Commander
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: WOW6432Node\Ghisler\Total Commander
        Recursive: false
        Comment: "Total Commander Registry artifacts"

# Third Party Applications -> TeamViewer - https://www.teamviewer.com/en-us/

    -
        Description: TeamViewer
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\TeamViewer
        ValueName: Meeting_UserName
        Recursive: false
        Comment: "Windows username of logged in user"
    -
        Description: TeamViewer
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\TeamViewer
        ValueName: BuddyLoginName
        Recursive: false
        Comment: "User's email associated with TeamViewer"
    -
        Description: TeamViewer
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\TeamViewer
        ValueName: BuddyDisplayName
        Recursive: false
        Comment: "User specified TeamViewer display name"
    -
        Description: TeamViewer
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: WOW6432Node\TeamViewer
        ValueName: OwningManagerAccountName
        Recursive: false
        Comment: "Displays the name of the user logged into TeamViewer"
    -
        Description: TeamViewer
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: WOW6432Node\TeamViewer
        ValueName: PermanentPasswordDate
        Recursive: false
        Comment: "Displays the date the password was last set for the user within TeamViewer"

# Third Party Applications -> Adobe - https://www.adobe.com/

    -
        Description: Adobe cRecentFiles
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Adobe
        Recursive: false
        Comment: "Displays files which were opened Adobe Reader by the user"

# Adobe plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Adobe
# https://www.forensafe.com/blogs/adobeacrobatreader.html

    -
        Description: Adobe cRecentFolders
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFolders\*
        ValueName: tDIText
        Recursive: false
        Comment: "Displays folders where Adobe Reader opened a PDF file from"

# Third Party Applications -> Visual Studio - https://visualstudio.microsoft.com/

    -
        Description: VisualStudio FileMRUList
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\VisualStudio\*\FileMRUList
        Recursive: false
        Comment: ""
    -
        Description: VisualStudio MRUItems
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\VisualStudio\*\MRUItems\*\Items
        Recursive: false
        Comment: ""
    -
        Description: VisualStudio MRUSettings
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\VisualStudio\*\NewProjectDialog\MRUSettingsLocalProjectLocationEntries
        Recursive: false
        Comment: ""

# Third Party Applications -> 7-Zip - https://www.7-zip.org/

    -
        Description: 7-Zip
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\7-Zip\Compression
        ValueName: ArcHistory
        Recursive: false
        Comment: "Displays list of files and folders that were used with 7-Zip"

# 7-ZipHistory plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.7-ZipHistory

# Third Party Applications -> WinRAR - https://www.rarlab.com/

    -
        Description: WinRAR
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\WinRAR
        Recursive: false
        Comment: "Displays history of archives that were used with WinRAR"

# WinRAR plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.WinRAR

# Third Party Applications -> Eraser - https://eraser.heidi.ie/

    -
        Description: Eraser
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Eraser
        Recursive: true
        Comment: "Potential evidence of anti-forensics"

# Third Party Applications -> LogMeIn - https://www.logmein.com/home2/v4

    -
        Description: LogMeIn
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\LogMeIn
        Recursive: true
        Comment: "LogMeIn GoToMeeting"

# Third Party Applications -> Macrium Reflect - https://www.macrium.com/

    -
        Description: Macrium Reflect
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Macrium\Reflect\Recent Folders\Image\*
        Recursive: false
        Comment: "Macrium Reflect image storage directory"
    -
        Description: Macrium Reflect
        HiveType: SYSTEM
        Category: Third Party Applications
        KeyPath: ControlSet*\Control\BackupRestore\FilesNotToSnapshotMacriumImage
        Recursive: true
        Comment: "Displays files that are not to be included in Macrium Reflect images"
    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium
        ValueName: LastRun
        Recursive: true
        Comment: "Command last ran by user"
    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium
        ValueName: Licensee
        Recursive: true
        Comment: "registered user"
    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium\Reflect\CBT\Sequence
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: true
        Comment: "Displays timestamps related to Macrium Reflect's CBT feature"

# https://knowledgebase.macrium.com/display/KNOW72/Macrium+Changed+Block+Tracker
# https://forum.macrium.com/PrintTopic35786.aspx

    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium\Reflect\Defaults
        Recursive: true
        Comment: "Displays default settings associated with Macrium Reflect on this computer"
    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium\Reflect\ImageGuardian
        Recursive: false
        Comment: "Displays Macrium Image Guardian status"
    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium\Reflect\Security
        ValueName: SID
        Recursive: true
        Comment: "Displays SID associated with Macrium Reflect on this computer"
    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium\Reflect\Security
        ValueName: App Path
        Recursive: true
        Comment: "Displays the application path associated with Macrium Reflect on this computer"
    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium\Reflect\MIG\Verified
        Recursive: true
        Comment: "Macrium Image Guardian Status, 1 = protected"
    -
        Description: Macrium Reflect
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Macrium\Reflect\VSS
        Recursive: true
        Comment: "Displays settings related to Macrium Reflect's interaction with VSS"

# Third Party Applications -> WinSCP - https://winscp.net/eng/index.php

    -
        Description: WinSCP
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Martin Prikryl
        Recursive: true
        Comment: "WinSCP"
    -
        Description: WinSCP
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: WOW6432Node\Martin Prikryl
        Recursive: true
        Comment: "WinSCP"

# Third Party Applications -> Ares - https://www.ares.net/

    -
        Description: Ares
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: Ares
        Recursive: true
        Comment: "Displays information relating to Ares"

# Ares plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Ares

# Third Party Applications -> Soulseek - https://www.slsknet.org/news/

    -
        Description: Soulseek
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{8A4E1646-488C-4E5B-AC31-F784400E8D2D}_is1
        ValueName: "Inno Setup: User"
        Recursive: true
        Comment: "Displays the name of the user who installed Soulseek"
    -
        Description: Soulseek
        HiveType: SOFTWARE
        Category: Third Party Applications
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{8A4E1646-488C-4E5B-AC31-F784400E8D2D}_is1
        ValueName: "Inno Setup: Language"
        Recursive: true
        Comment: "Displays the language for which Soulseek was installed"

# Third Party Applications -> Signal - https://signal.org/en/

    -
        Description: Signal
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\7d96caee-06e6-597c-9f2f-c7bb2e0948b4
        ValueName: InstallLocation
        Recursive: true
        Comment: "Displays the location where Signal is installed on the user's computer"

# Third Party Applications -> Stardock Fences - https://www.stardock.com/products/fences/

    -
        Description: Stardock Fences
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Stardock\Fences\InitialSnapshot
        Recursive: true
        Comment: "Displays a list of links the user had on their desktop at the time of installation"
    -
        Description: Stardock Fences
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Stardock\Fences\Icons
        Recursive: true
        Comment: "Displays a list of icons on the user's desktop"
    -
        Description: Stardock Fences
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Stardock\Fences\Settings
        ValueName: ResolutionLast
        Recursive: true
        Comment: "Displays a list of connected monitors to the user's computer"
    -
        Description: Stardock Fences
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: Software\Stardock\Fences\Settings
        ValueName: PrimaryMonitorLast
        Recursive: true
        Comment: "Displays the user's primary monitor"

# Third Party Applications -> 4K Video Downloader - https://www.4kdownload.com/products/videodownloader/1

    -
        Description: 4K Video Downloader
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\4kdownload.com\4K Video Downloader\Notification
        ValueName: runCount
        Recursive: false
        Comment: "Displays the run count for 4K Video Downloader"
    -
        Description: 4K Video Downloader
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\4kdownload.com\4K Video Downloader\Notification
        ValueName: lastVersion
        Recursive: false
        Comment: "Displays the last version of 4K Video Downloader installed on this system"
    -
        Description: 4K Video Downloader
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\4kdownload.com\4K Video Downloader\Limits
        ValueName: dayDownloadDate
        IncludeBinary: true
        BinaryConvert: EPOCH
        Recursive: false
        Comment: "Displays the date that 4K Video Downloader was installed"
    -
        Description: 4K Video Downloader
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\4kdownload.com\4K Video Downloader\Limits
        ValueName: dayDownloadCount
        Recursive: false
        Comment: "Displays the amount of times 4K Video Downloaded was downloaded"
    -
        Description: 4K Video Downloader
        HiveType: NTUSER
        Category: Third Party Applications
        KeyPath: SOFTWARE\4kdownload.com\4K Video Downloader\Download
        ValueName: downloadedItemsDb
        Recursive: false
        Comment: "Displays the location of the SQLite database associated with 4K Video Downloader"

# --------------------
# CLOUD STORAGE
# --------------------

# Cloud Storage -> OneDrive

    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\Microsoft\Office\*\Common\Internet\Server*\http*\*
        Recursive: false
        Comment: "Displays folders present within a user's OneDrive"
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Environment
        ValueName: OneDriveConsumer
        Recursive: false
        Comment: "Displays the user's (check HivePath) specified storage location for OneDrive"
    -
        Description: OneDrive
        HiveType: SOFTWARE
        Category: Cloud Storage
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\OneDrive*\UserSyncRoots
        Recursive: true
        Comment: "Displays the user's specified storage location for OneDrive"
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\SyncEngines\Providers\OneDrive\*\
        ValueName: LastModifiedTime
        Recursive: true
        Comment: "Displays the Last Modified time for the OneDrive Registry key"
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\SyncEngines\Providers\OneDrive\*\
        ValueName: MountPoint
        Recursive: true
        Comment: "Displays where the OneDrive folder is mounted"
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\SyncEngines\Providers\OneDrive\*\
        ValueName: UrlNamespace
        Recursive: true
        Comment: "Displays the URL Namespace for OneDrive"
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\SyncEngines\Providers\OneDrive\*\
        ValueName: IsOfficeSyncIntegrationEnabled
        Recursive: true
        Comment: "Office Sync Integration, 0 = Disabled, 1 = Enabled"
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\SyncEngines\Providers\OneDrive\*\
        ValueName: LibraryType
        Recursive: true
        Comment: ""
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\Microsoft\OneDrive\*\
        ValueName: InstallPath
        Recursive: true
        Comment: "Displays the installation path from the user's AppData folder for OneDrive"
    -
        Description: OneDrive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\Microsoft\OneDrive\Accounts
        ValueName: LastUpdate
        IncludeBinary: true
        BinaryConvert: EPOCH
        Recursive: true
        Comment: "Displays the last update time of the Accounts OneDrive Registry key"

# Cloud Storage -> Dropbox

    -
        Description: Dropbox
        HiveType: SOFTWARE
        Category: Cloud Storage
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\Dropbox*\UserSyncRoots
        Recursive: true
        Comment: "Displays the user's specified storage location for Dropbox"

# --------------------
# SERVICES
# --------------------

    -
        Description: Services
        HiveType: SYSTEM
        Category: Services
        KeyPath: ControlSet*\Services
        Recursive: false
        Comment: "Displays list of services running on this computer"

# Services plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Services
# https://www.forensafe.com/blogs/windowsservices.html

# --------------------
# EVENT LOGS
# --------------------

    -
        Description: Event Logs Logging Status
        HiveType: SOFTWARE
        Category: Event Logs
        KeyPath: Microsoft\Windows\CurrentVersion\WINEVT\Channels
        ValueName: Enabled
        Recursive: true
        Comment: "Displays the status of Windows Event Log Channels (Key Path) on this system, 0 = Disabled, 1 - Enabled"

# https://www.ibm.com/mysupport/s/question/0D50z000062kolQ/how-to-monitor-custom-event-log?language=en_US
# SYSTEM\\ControlSet00*\Services\EventLog\* will display the Provider GUID for each Event Log channel listed here. This recursive key is not enabled here

    -
        Description: Application Event Log Providers
        HiveType: SYSTEM
        Category: Event Logs
        KeyPath: ControlSet001\Control\WMI\Autologger\EventLog-Application
        Recursive: true
        Comment: "Displays the status of Providers within the Application Event Log on this system, 0 = Disabled, 1 - Enabled"

# ETW plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.ETW

    -
        Description: System Event Log Providers
        HiveType: SYSTEM
        Category: Event Logs
        KeyPath: ControlSet001\Control\WMI\Autologger\EventLog-System
        Recursive: true
        Comment: "Displays the status of Providers within the Application Event Log on this system, 0 = Disabled, 1 - Enabled"

# ETW plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.ETW

# --------------------
# MICROSOFT OFFICE/OFFICE 365
# --------------------

#    -
#        Description: Microsoft Office
#        HiveType: NTUSER
#        Category: Microsoft Office
#        KeyPath: Software\Microsoft\Office
#        Recursive: true
#        Comment: "Microsoft Office Registry artifacts"
#
# Uncomment this if you want ALL Registry artifacts for Microsoft Office. Be sure to comment out the below values since you won't need them anymore. On my system, recursive on the entire MS Office key returned 16,000+ lines.

    -
        Description: Microsoft Office
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\Common\Identity\Identities\*
        ValueName: EmailAddresses
        Recursive: false
        Comment: "Lists email addresses registered to Microsoft Office on the user's system"
    -
        Description: Microsoft Office
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\Common\Identity\Identities\*
        ValueName: EmailAddress
        Recursive: false
        Comment: "Lists email address registered to Microsoft Office on the user's system"
    -
        Description: Microsoft Office
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\Common\Identity\Identities\*
        ValueName: FirstName
        Recursive: false
        Comment: "Lists first name for the registered Microsoft Office user"
    -
        Description: Microsoft Office
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\Common\Identity\Identities\*
        ValueName: LastName
        Recursive: false
        Comment: "Lists last name for the registered Microsoft Office user"
    -
        Description: Microsoft Office
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\Common\Identity\Identities\*
        ValueName: FriendlyName
        Recursive: false
        Comment: "Lists full name for the registered Microsoft Office user"
    -
        Description: Microsoft Office
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\Common\Identity\Identities\*
        ValueName: Initials
        Recursive: false
        Comment: "Lists initials for the registered Microsoft Office user"
    -
        Description: Microsoft Office
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\Common\Identity\Identities\*\AuthHistory
        Recursive: true
        IncludeBinary: true
        BinaryConvert: FILETIME
        Comment: "Displays time user was authenticated to the system's instance of Microsoft 365 for the first time"
    -
        Description: Microsoft Office
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\Common\Identity\Profiles\*
        Recursive: true
        Comment: "Displays time user was authenticated to the system's instance of Microsoft 365 for the first time"
    -
        Description: Microsoft Office Trusted Documents
        HiveType: NTUSER
        Category: Microsoft Office
        KeyPath: Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords
        Recursive: true
        Comment: "Displays list of Office documents where the user may have clicked Enable Editing, Enable Macro, or Enable Content"

# TrustedDocuments plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.TrustedDocuments

# --------------------
# MICROSOFT EXCHANGE
# --------------------

# Microsoft Exchange -> Microsoft Exchange Patch Status

    -
        Description: Microsoft Exchange Patch Status
        HiveType: SOFTWARE
        Category: Microsoft Exchange
        KeyPath: Microsoft\Updates\Exchange*\KB*
        Recursive: false
        ValueName: InstalledDate
        Comment: "Displays the date the patch was installed on this host"
    -
        Description: Microsoft Exchange Patch Status
        HiveType: SOFTWARE
        Category: Microsoft Exchange
        KeyPath: Microsoft\Updates\Exchange*\KB*
        Recursive: false
        ValueName: PackageName
        Comment: "Displays the name of the patch installed on this host"
    -
        Description: Microsoft Exchange Patch Status
        HiveType: SOFTWARE
        Category: Microsoft Exchange
        KeyPath: Microsoft\Updates\Exchange*\SP*\KB*
        Recursive: false
        ValueName: InstalledDate
        Comment: "Displays the date the patch was installed on this host"
    -
        Description: Microsoft Exchange Patch Status
        HiveType: SOFTWARE
        Category: Microsoft Exchange
        KeyPath: Microsoft\Updates\Exchange*\SP*\KB*
        Recursive: false
        ValueName: PackageName
        Comment: "Displays the name of the patch installed on this host"

# https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-march-2-2021-kb5000871-9800a6bb-0a21-4ee7-b9da-fa85b3e1d23b

# --------------------
# WEB BROWSERS
# --------------------

    -
        Description: Google Chrome
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Google\Chrome
        Recursive: true
        Comment: "Google Chrome Registry artifacts"
    -
        Description: Internet Explorer
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Internet Explorer\Main
        IncludeBinary: true
        Recursive: false
        Comment: "Internet Explorer Registry artifacts"
    -
        Description: Internet Explorer
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Internet Explorer
        ValueName: Download Directory
        Recursive: false
        Comment: "Internet Explorer Registry artifacts"
    -
        Description: Internet Explorer
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Internet Explorer\NewWindows
        Recursive: false
        Comment: "Internet Explorer Registry artifacts"
    -
        Description: Internet Explorer
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Internet Explorer\Suggested Sites\*
        IncludeBinary: true
        Recursive: false
        Comment: "Internet Explorer Registry artifacts"
    -
        Description: Internet Explorer
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Internet Explorer\ProtocolExecute\*
        Recursive: false
        Comment: "Internet Explorer Registry artifacts"
    -
        Description: Internet Explorer
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Internet Explorer\LowRegistry\IEShims
        Recursive: true
        Comment: "Internet Explorer Registry artifacts"
    -
        Description: Internet Explorer
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Internet Explorer\Main\WindowsSearch
        Recursive: true
        Comment: "Internet Explorer Registry artifacts"
    -
        Description: Internet Explorer
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Internet Explorer\Main\WindowsSearch
        IncludeBinary: true
        Recursive: false
        Comment: "Internet Explorer Registry artifacts"
    -
        Description: Microsoft Edge
        HiveType: NTUSER
        Category: Web Browsers
        KeyPath: Software\Microsoft\Edge
        Recursive: true
        Comment: "Microsoft Edge Registry artifacts"
    -
        Description: CCleaner Browser
        HiveType: SOFTWARE
        Category: Web Browsers
        KeyPath: WOW6432Node\Piriform\Browser
        IncludeBinary: true
        Recursive: true
        Comment: "CCleaner Browser Registry artifacts"

# --------------------
# INSTALLED SOFTWARE
# --------------------

    -
        Description: App Paths
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: Microsoft\Windows\CurrentVersion\App Paths
        Recursive: false
        Comment: "Displays list of installed software and the associated application paths"

# AppPaths plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.AppPaths

    -
        Description: File Extensions
        HiveType: NTUSER
        Category: Installed Software
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts
        Recursive: false
        Comment: "Tracks programs associated with file extensions"

# FileExts plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.FileExts
# https://www.marshall.edu/forensics/files/Brewer-PosterFinal.pdf
# https://digital-forensics.sans.org/summit-archives/2012/taking-registry-analysis-to-the-next-level.pdf

# Installed Software -> Add/Remove Program Entries
    -
        Description: Add/Remove Programs Entries
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: false
        Comment: "Displays installed software"

# Uninstall plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Uninstall
# https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/find-installed-software

    -
        Description: Add/Remove Programs Entries
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: false
        Comment: "Displays installed software"

# Uninstall plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Uninstall
# https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/find-installed-software

    -
        Description: Add/Remove Programs Entries
        HiveType: NTUSER
        Category: Installed Software
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: false
        Comment: "Displays installed software"

# Uninstall plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Uninstall
# https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/find-installed-software
# https://www.advancedinstaller.com/user-guide/registry-wow6432-node.html
# https://docs.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry

    -
        Description: Products
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products
        Recursive: false
        Comment: "Displays all installed software packages"

# Products plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.Uninstall
# https://www.nirsoft.net/utils/installed_packages_view.html

    -
        Description: Windows App List
        HiveType: UsrClass
        Category: Installed Software
        KeyPath: Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository
        Recursive: false
        Comment: "Displays all Windows applications installed on this system"

# WindowsApp plugin - https://github.com/EricZimmerman/RegistryPlugins/tree/master/RegistryPlugin.WindowsApp
# https://www.datadigitally.com/2019/05/windows-10-specific-registry-keys.html
# This batch file currently only supports UsrClass parsing. Other hive didn't appear to be working when testing in Registry Explorer

# --------------------
# VOLUME SHADOW COPIES
# --------------------

# https://docs.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-portal

    -
        Description: VSS
        HiveType: SYSTEM
        Category: Volume Shadow Copies
        KeyPath: ControlSet*\Control\BackupRestore\FilesNotToSnapshot
        Recursive: true
        Comment: "Displays files to be deleted from newly created shadow copies"

# https://medium.com/@bromiley/windows-wednesday-volume-shadow-copies-d20b60997c22#.11p1cb258
# https://docs.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore#filesnottosnapshot

    -
        Description: VSS
        HiveType: SYSTEM
        Category: Volume Shadow Copies
        KeyPath: ControlSet*\Control\BackupRestore\FilesNotToSnapshotSave
        Recursive: true
        Comment: "Displays files to be deleted from newly created shadow copies"

# https://medium.com/@bromiley/windows-wednesday-volume-shadow-copies-d20b60997c22#.11p1cb258
# https://docs.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore

    -
        Description: VSS
        HiveType: SYSTEM
        Category: Volume Shadow Copies
        KeyPath: ControlSet*\Control\BackupRestore\KeysNotToRestore
        Recursive: true
        Comment: "Displays the names of the Registry subkeys and values that backup applications should not restore"

# https://medium.com/@bromiley/windows-wednesday-volume-shadow-copies-d20b60997c22#.11p1cb258
# https://docs.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore#keysnottorestore

    -
        Description: VSS
        HiveType: SYSTEM
        Category: Volume Shadow Copies
        KeyPath: ControlSet*\Control\BackupRestore\FilesNotToBackup
        Recursive: true
        Comment: "Displays the names of the files and directories that backup applications should not backup or restore"

# https://medium.com/@bromiley/windows-wednesday-volume-shadow-copies-d20b60997c22#.11p1cb258
# https://docs.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore#filesnottobackup

# --------------------
# THREAT HUNTING
# --------------------

    -
        Description: Shadow RDP Sessions
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows NT\Terminal Services
        ValueName: Shadow
        Recursive: true
        Comment: "Shadow RDP sessions, 0 = Disabled, 1 = Full Control with user's permission, 2 = Full Control without user's permission, 3 = View Session with user's permission, 4 = View Session without user's permission"

# https://twitter.com/inversecos/status/1380006149479559170
# https://bitsadm.in/blog/spying-on-users-using-rdp-shadowing

    -
        Description: RDP Connections Status
        HiveType: SYSTEM
        Category: Threat Hunting
        KeyPath: ControlSet*\Control\Terminal Server
        ValueName: fDenyTSConnections
        Recursive: true
        Comment: "Displays the status of whether the system can accept Terminal Server (RDP) connections, 0 = Disabled (Inbound RDP enabled), 1 = Enabled (Inbound RDP disabled)"

# https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-localsessionmanager-fdenytsconnections

    -
        Description: RDP User Authentication Status
        HiveType: SYSTEM
        Category: Threat Hunting
        KeyPath: ControlSet*\Control\Terminal Server\WinStations\RDP-Tcp
        ValueName: UserAuthentication
        Recursive: true
        Comment: "Displays whether a Network-Level user authentication is required before a remote desktop connection is established. 0 = Disabled (no authentication required), 1 = Enabled (authentication required)"

# https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-userauthentication

    -
        Description: Windows Defender Status
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows Defender
        ValueName: DisableAntiSpyware
        Recursive: true
        Comment: "Displays the status of whether Windows Defender AntiSpyware is enabled or not. 0 = Enabled, 1 = Disabled"

# https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-disableantispyware
# https://answers.microsoft.com/en-us/protect/forum/all/how-to-kill-antimalware-service-executable/b5ce5b46-a65b-460c-b4cd-e2cca50358cf
# https://gist.github.com/MHaggis/a955f1351a7d07592b90ab605e3b02d9

    -
        Description: Windows Defender Status
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows Defender
        ValueName: DisableAntiVirus
        Recursive: true
        Comment: "Displays the status of whether Windows Defender AntiVirus is enabled or not. 0 = Enabled, 1 = Disabled"

# https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-disableantispyware
# https://answers.microsoft.com/en-us/protect/forum/all/how-to-kill-antimalware-service-executable/b5ce5b46-a65b-460c-b4cd-e2cca50358cf
# https://gist.github.com/MHaggis/a955f1351a7d07592b90ab605e3b02d9

    -
        Description: Windows Defender
        HiveType: SOFTWARE
        Category: Antivirus
        KeyPath: Microsoft\Windows Defender\SpyNet
        ValueName: DisableBlockAtFirstSeen
        Recursive: false
        Comment: "Windows Defender DisableBlockAtFirstSeen Status, 0 = Disabled, 1 = Enabled"

# https://gist.github.com/MHaggis/a955f1351a7d07592b90ab605e3b02d9

    -
        Description: Windows Defender
        HiveType: SOFTWARE
        Category: Antivirus
        KeyPath: Microsoft\Windows Defender\SpyNet
        ValueName: SpynetReporting
        Recursive: false
        Comment: "Windows Defender SpynetReporting Status, 0 = Disabled, 1 = Enabled"

# https://gist.github.com/MHaggis/a955f1351a7d07592b90ab605e3b02d9

    -
        Description: Windows Defender
        HiveType: SOFTWARE
        Category: Antivirus
        KeyPath: Microsoft\Windows Defender\SpyNet
        ValueName: SubmitSamplesConsent
        Recursive: false
        Comment: "Windows Defender SubmitSamplesConsent Status, 0 = Disabled, 1 = Enabled"

# https://gist.github.com/MHaggis/a955f1351a7d07592b90ab605e3b02d9

    -
        Description: PortProxy Configuration
        HiveType: SYSTEM
        Category: Threat Hunting
        KeyPath: ControlSet*\Services\PortProxy\v4tov4\tcp
        Recursive: true
        Comment: "Displays current port proxy configuration"

# https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
# https://adepts.of0x.cc/netsh-portproxy-code/
# https://www.dfirnotes.net/portproxy_detection/

    -
        Description: Exefile Shell Open Command
        HiveType: Software
        Category: Threat Hunting
        KeyPath: Classes\Exefile\Shell\Open\Command
        ValueName: (default)
        Recursive: false
        Comment: Exefile hijack shows e.g. path to a binary

    -
        Description: Exefile Shell Open Command
        HiveType: usrclass
        Category: Threat Hunting
        KeyPath: Exefile\Shell\Open\Command
        ValueName: (default)
        Recursive: false
        Comment: Exefile hijack shows e.g. path to a binary

# https://twitter.com/swisscom_csirt/status/1461686311769759745
# https://attack.mitre.org/techniques/T1546/001/

# Threat Hunting -> Hades - Located within a PowerShell script associated with this group

    -
        Description: Hades IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: UseAdvancedStartup
        Recursive: false
        Comment: "0 = Disabled, 1 = Enabled"
    -
        Description: Hades IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: EnableBDEWithNoTPM
        Recursive: false
        Comment: "1 = Default, 0 = Disabled, 1 = Enabled"
    -
        Description: Hades IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: UseTPM
        Recursive: false
        Comment: "0 = Do Not Allow TPM, 1 = Require TPM, 2 = Allow TPM"
    -
        Description: Hades IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: UseTPMKey
        Recursive: false
        Comment: "0 = Do not allow startup key with TPM, 1 = Require startup key with TPM, 2 = Allow startup key with TPM"
    -
        Description: Hades IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: UseTPMKeyPIN
        Recursive: false
        Comment: "0 = Do not allow startup key and PIN with TPM, 1 = Require startup key and PIN with TPM, 2 = Allow startup key and PIN with TPM"
    -
        Description: Hades IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: RecoveryKeyMessage
        Recursive: false
        Comment: "Displays the Recovery Key message set by the Threat Actor group"
    -
        Description: Hades IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: RecoveryKeyMessageSource
        Recursive: false
        Comment: "2 is set by the Hades group"
    -
        Description: Hades IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: UseTPMPIN
        Recursive: false
        Comment: "0 = Do not allow startup PIN with TPM, 1 = Require startup PIN with TPM, 2 = Allow startup PIN with TPM"

# https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.VolumeEncryption::ConfigureAdvancedStartup_Name

# Threat Hunting -> Kaseya (REvil - July 2021) - Located within Registry hives from an infected system

    -
        Description: REvil IOCs
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Wow6432Node\BlackLivesMatter
        Recursive: true
        Comment: "REvil/Kaseya Ransomware attack from July 2021"

# https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers
# https://www.huntress.com/blog/rapid-response-kaseya-vsa-mass-msp-ransomware-incident
# https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/kaseya-ransomware-supply-chain

# Threat Hunting -> Lockbit 2.0 - Located within Registry hives from an infected system

    -
        Description: PowerShell Info
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Microsoft\PowerShell\info
        Recursive: false
        Comment: Cobalt Strike Reflection Attack - Lockbit 2.0

    -
        Description: Restricted Admin Status
        HiveType: SYSTEM
        Category: Threat Hunting
        KeyPath: ControlSet*\Control\Lsa
        ValueName: DisableRestrictedAdmin
        Recursive: false
        Comment: "Displays the status of Restricted Admin mode"

# https://twitter.com/JohnLaTwC/status/1413510338880839686
# https://labs.f-secure.com/blog/undisable/
# https://blog.ahasayen.com/restricted-admin-mode-for-rdp/
# https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard

# Threat Hunting -> Antivirus

    -
        Description: Windows Defender
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Microsoft\Windows Defender\Real-Time Protection
        Recursive: false
        Comment: "Windows Defender Real-Time Protection Status, 0 = Enabled, 1 = Disabled"

# https://www.windowsphoneinfo.com/threads/cannot-open-security-dashboard-for-windows-defender.114537/
# https://gist.github.com/MHaggis/a955f1351a7d07592b90ab605e3b02d9

    -
        Description: Symantec Endpoint Protection
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: WOW6432Node\Symantec\Symantec Endpoint Protection\AV\Quarantine\QRecords\*
        ValueName: FName
        Recursive: false
        Comment: "Displays a list of filenames that have been quarantined by Symantec Endpoint Protection"
    -
        Description: Windows Defender
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Microsoft\Windows Defender\Reporting
        Recursive: false
        Comment: "Windows Defender Real-Time Protection Status, 0 = Enabled, 1 = Disabled"
    -
        Description: Windows Defender
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Microsoft\Windows Defender
        ValueName: fDenyTSConnections
        Recursive: false
        Comment: "Windows Defender Real-Time Protection Status, 0 = Enabled, 1 = Disabled"
    -
        Description: Windows Defender
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Policies\Microsoft\Windows Defender\Exclusions\
        Recursive: true
        Comment: "Windows Defender Exclusions through Group Policies (GPOs)"
    -
        Description: Windows Defender
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Microsoft\Windows Defender\Exclusions\
        Recursive: true
        Comment: "Windows Defender Exclusions"
    -
        Description: Image File Execution Options Injection
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*
        ValueName: Debugger
        Recursive: false
        Comment: "See documentation in Batch File for further information"

# https://attack.mitre.org/techniques/T1546/012/

    -
        Description: Image File Execution Options Injection
        HiveType: SOFTWARE
        Category: Threat Hunting
        KeyPath: Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*
        Recursive: false
        Comment: "See documentation in Batch File for further information"

# https://attack.mitre.org/techniques/T1546/012/

# Threat Hunting -> Office

    -
        Description: Connections Made By MS Office
        HiveType: NTUSER
        Category: Threat Hunting
        KeyPath: Software\Microsoft\Office\*\Common\Internet\Server Cache
        Recursive: true
        Comment: "Displays the connections made by MS Office - IOCs found here for CVE-2022-30190"

# https://twitter.com/RoxpinTeddy/status/1531726171292983297?t=yan4rRk3w1epMk2Vxncfxw&s=19
# https://businessinsights.bitdefender.com/technical-advisory-cve-2022-30190-zero-day-vulnerability-follina-in-microsoft-support-diagnostic-tool

# More to come...stay tuned!
