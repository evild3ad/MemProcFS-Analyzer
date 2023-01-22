Description: Registry ASEPs
Author: Troy Larson
Version: 1
Id: d6b50e3a-291c-4d8a-afbc-4dd05d252742
Keys:
    -
        Description: Select ControlSet
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: Select
        Recursive: false
        Comment:
    -
        Description: ServiceControlManagerExtension
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control
        ValueName: ServiceControlManagerExtension
        Recursive: false
        Comment:
    -
        Description: BootVerificationProgram
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\BootVerificationProgram
        ValueName: Imagepath
        Recursive: false
        Comment:
    -
        Description: LSA Authentication Packages
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\LSA
        ValueName: Authentication Packages
        Recursive: false
        Comment: 
    -
        Description: LSA Notification Packages
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\LSA
        ValueName: Notification Packages
        Recursive: false
        Comment: 
    -
        Description: LSA Security Packages
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\LSA
        ValueName: Security Packages
        Recursive: false
        Comment: 
    -
        Description: LSA OsConfig
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\LSA\OsConfig
        ValueName: Security Packages
        Recursive: false
        Comment: 
    -
        Description: NetworkProvider Order
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: \ControlSet*\Control\NetworkProvider\*
        ValueName: ProviderOrder
        Recursive: true
        Comment: 
    -
        Description: Print Driver
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Print\Monitors\*
        ValueName: Driver
        Recursive: true
        Comment: 
    -
        Description: Print Providers
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Print\Providers\*
        ValueName: Name
        Recursive: true
        Comment: 
    -
        Description: SafeBoot
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: \ControlSet*\Control\SafeBoot
        ValueName: AlternateShell
        Recursive: false
        Comment: 
    -
        Description: SafeBoot Minimal
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\SafeBoot\Minimal\*
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: SafeBoot Network
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\SafeBoot\Network\*
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: SecurityProviders
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\SecurityProviders
        ValueName: SecurityProviders
        Recursive: false
        Comment: 
    -
        Description: Session Manager BootExecute
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: BootExecute
        Recursive: false
        Comment: 
    -
        Description: Session Manager BootShell
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: BootShell
        Recursive: false
        Comment: 
    -
        Description: Session Manager Execute
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: Execute
        Recursive: false
        Comment: 
    -
        Description: Session Manager InitialCommand
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: InitialCommand
        Recursive: false
        Comment: 
    -
        Description: Session Manager InitialCommand
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: "*InitialCommand"
        Recursive: false
        Comment: 
    -
        Description: Session Manager PendingFileRenameOperations
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: PendingFileRenameOperations
        Recursive: false
        Comment: 
    -
        Description: Session Manager PendingFileRenameOperations*
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: PendingFileRenameOperations*
        Recursive: false
        Comment: 
    -
        Description: Session Manager SETUPEXECUTE
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: SetUpExecute
        Recursive: false
        Comment: 
    -
        Description: Session Manager KnownDLLs
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager\KnownDLLs
        Recursive: false
        Comment: 
    -
        Description: Session Manager SubSystems
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Session Manager\SubSystems
        Recursive: false
        Comment: 
    -
        Description: Terminal Server StartupPrograms
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Terminal Server\Wds\rdpwd
        ValueName: StartupPrograms
        Recursive: false
        Comment: 
    -
        Description: Terminal Server WinStations RDP-Tcp
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: \ControlSet*\Control\Terminal Server\WinStations\RDP-Tcp\TSMMRemotingAllowedApps
        Recursive: false
        Comment: 
    -
        Description: WOW KnownDLLs
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\WOW
        ValueName: KnownDLLs
        Recursive: false
        Comment: 
    -
        Description: Services AutoRun
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: AutoRun
        Recursive: true
        Comment: 
    -
        Description: Services BootFlags
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: BootFlags
        Recursive: true
        Comment: 
    -
        Description: Services DelayedAutoStart
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: DelayedAutoStart
        Recursive: true
        Comment: 
    -
        Description: Services DependOnService
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: DependOnService
        Recursive: true
        Comment: 
    -
        Description: Services Description
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: Description
        Recursive: true
        Comment: 
    -
        Description: Services DisplayName
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: DisplayName
        Recursive: true
        Comment: 
    -
        Description: Services ErrorControl
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: ErrorControl
        Recursive: true
        Comment: 
    -
        Description: Services Group
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: Group
        Recursive: true
        Comment: 
    -
        Description: Services ImagePath
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: ImagePath
        Recursive: true
        Comment: 
    -
        Description: Services Library
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: Library
        Recursive: true
        Comment: 
    -
        Description: Services ObjectName
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: ObjectName
        Recursive: true
        Comment: 
    -
        Description: Services ProviderPath
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: ProviderPath
        Recursive: true
        Comment: 
    -
        Description: Services ProxyDllFile
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: ProxyDllFile
        Recursive: true
        Comment: 
    -
        Description: Services RequiredPrivileges
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: RequiredPrivileges
        Recursive: true
        Comment: 
    -
        Description: Services ServiceDll
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: ServiceDll
        Recursive: true
        Comment: 
    -
        Description: Services ServiceMain
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: ServiceMain
        Recursive: true
        Comment: 
    -
        Description: Services ServiceSidType
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: ServiceSidType
        Recursive: true
        Comment: 
    -
        Description: Services Start
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: Start
        Recursive: true
        Comment: 
    -
        Description: Services Type
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\*
        ValueName: Type
        Recursive: true
        Comment: 
    -
        Description: WinSock2 AppId_Catalog AppFullPath
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\AppId_Catalog\*
        ValueName: AppFullPath
        Recursive: false
        Comment: 
    -
        Description: WinSock2 AppId_Catalog AppArgs
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\AppId_Catalog\*
        ValueName: AppArgs
        Recursive: false
        Comment: 
    -
        Description: WinSock2 NameSpace_Catalog5 DisplayString
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\*
        ValueName: DisplayString
        Recursive: false
        Comment: 
    -
        Description: WinSock2 NameSpace_Catalog5 Enabled
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\*
        ValueName: Enabled
        Recursive: false
        Comment: 
    -
        Description: WinSock2 NameSpace_Catalog5 LibraryPath
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\*
        ValueName: LibraryPath
        Recursive: false
        Comment: 
    -
        Description: WinSock2 NameSpace_Catalog5 64 DisplayString
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\*
        ValueName: DisplayString
        Recursive: false
        Comment: 
    -
        Description: WinSock2 NameSpace_Catalog5 64 Enabled
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\*
        ValueName: Enabled
        Recursive: false
        Comment: 
    -
        Description: WinSock2 NameSpace_Catalog5 64 LibraryPath
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\*
        ValueName: LibraryPath
        Recursive: false
        Comment: 
    -
        Description: WinSock2 Protocol_Catalog9 ProtocolName
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\*
        ValueName: ProtocolName
        Recursive: false
        Comment: 
    -
        Description: WinSock2 Protocol_Catalog9 64 ProtocolName
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64\*
        ValueName: ProtocolName
        Recursive: false
        Comment: 
    -
        Description: Setup
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: Setup
        ValueName: CmdLine
        Recursive: false
        Comment: 
    -
        Description: .cmd
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\.cmd
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: .cmd PersistentHandler
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\.cmd\PersistentHandler
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: .exe
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\.exe
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: .exe PersistentHandler
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\.exe\PersistentHandler
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: shell Open Command
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\*\shell
        ValueName: DelegateExecute
        Recursive: true
        Comment:
    -
        Description: shell Runas command
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\*\shell
        ValueName: IsolatedCommand
        Recursive: true
        Comment: 
    -
        Description: ShellEx ColumnHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\*\ShellEx\ColumnHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx ContextMenuHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\*\ShellEx\ContextMenuHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: shellex ContextMenuHandlers InstallFont
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\*\shellex\ContextMenuHandlers\InstallFont
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: shellex ContextMenuHandlers Open With
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\*\shellex\ContextMenuHandlers\Open With
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: shellex ContextMenuHandlers Open With EncryptionMenu
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\*\shellex\ContextMenuHandlers\Open With EncryptionMenu
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx ContextMenuHandlers OpenContainingFolderMenu
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\*\ShellEx\ContextMenuHandlers\OpenContainingFolderMenu
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: shellex ContextMenuHandlers PlayTo
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\*\shellex\ContextMenuHandlers\PlayTo
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx CopyHookHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\*\ShellEx\CopyHookHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx DragDropHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\*\ShellEx\DragDropHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx ExtShellFolderViews
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\*\ShellEx\ExtShellFolderViews
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEX IconHandler
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\*\ShellEX\IconHandler
        Recursive: false
        Comment: 
    -
        Description: ShellEx PropertySheetHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\*\ShellEx\PropertySheetHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: CLSID InprocServer32
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\InprocServer32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: CLSID InprocServer32
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\InprocServer32
        ValueName: Assembly
        Recursive: false
        Comment: 
    -
        Description: CLSID Instance CLSID
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\Instance
        ValueName: CLSID
        Recursive: true
        Comment: 
    -
        Description: CLSID Instance FriendlyName
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\Instance
        ValueName: FriendlyName
        Recursive: true
        Comment: 
    -
        Description: CLSID LocalServer32
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\LocalServer32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: CLSID LocalServer32
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\LocalServer32
        ValueName: Assembly
        Recursive: false
        Comment: 
    -
        Description: CLSID PersistentHandler
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\PersistentHandler
        Recursive: false
        Comment: 
    -
        Description: CLSID TypeLib
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\TypeLib
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: cmdfile shell open command
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\cmdfile\shell\open\command
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Directory background shellex ContextMenuHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Directory\background\shellex\ContextMenuHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Directory shellex CopyHookHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Directory\shellex\CopyHookHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Directory shellex DragDropHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Directory\shellex\DragDropHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Directory shellex PropertySheetHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Directory\shellex\PropertySheetHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Drive shellex ContextMenuHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Drive\shellex\ContextMenuHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Exefile Shell Open Command
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Exefile\Shell\Open\Command
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Classes Filter
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Filter
        Recursive: true
        Comment: 
    -
        Description: Folder shellex ContextMenuHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Folder\shellex\ContextMenuHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Folder shellex DragDropHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Folder\shellex\DragDropHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Folder shellex PropertySheetHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Folder\shellex\PropertySheetHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: htmlfile shell open command
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\htmlfile\shell\open\command
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Interface ProxyStubClsid32
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Interface\*\ProxyStubClsid32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Interface TypeLib
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Interface\*\TypeLib
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Protocols Filter
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Protocols\Filter\*
        ValueName: CLSID
        Recursive: false
        Comment: 
    -
        Description: Protocols Handler
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Protocols\Handler\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Protocols Handler
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Protocols\Handler\*
        ValueName: CLSID
        Recursive: false
        Comment: 
    -
        Description: Protocols Name-Space Handler
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Protocols\Name-Space Handler\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Protocols Name-Space Handler
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Protocols\Name-Space Handler\*
        ValueName: CLSID
        Recursive: false
        Comment: 
    -
        Description: SystemFileAssociations ShellEx ContextMenuHandlers ShellImagePreview
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\SystemFileAssociations\*\ShellEx\ContextMenuHandlers\ShellImagePreview
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: TypeLib win32
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\TypeLib\*\*\*\win32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: TypeLib win64
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\TypeLib\*\*\*\win64
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 shell Open Command
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\*\shell
        ValueName: DelegateExecute
        Recursive: true
        Comment:
    -
        Description: Wow6432 shell Runas command
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\*\shell
        ValueName: IsolatedCommand
        Recursive: true
        Comment: 
    -
        Description: Wow6432 ShellEx ColumnHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\*\ShellEx\ColumnHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 ShellEx ContextMenuHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\*\ShellEx\ContextMenuHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 shellex ContextMenuHandlers InstallFont
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\*\shellex\ContextMenuHandlers\InstallFont
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 shellex ContextMenuHandlers Open With
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\*\shellex\ContextMenuHandlers\Open With
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 shellex ContextMenuHandlers Open With EncryptionMenu
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\*\shellex\ContextMenuHandlers\Open With EncryptionMenu
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 ShellEx ContextMenuHandlers OpenContainingFolderMenu
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\*\ShellEx\ContextMenuHandlers\OpenContainingFolderMenu
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 shellex ContextMenuHandlers PlayTo
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\*\shellex\ContextMenuHandlers\PlayTo
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 ShellEx CopyHookHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\*\ShellEx\CopyHookHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 ShellEx DragDropHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\*\ShellEx\DragDropHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 ShellEx ExtShellFolderViews
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\*\ShellEx\ExtShellFolderViews
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 ShellEX IconHandler
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\*\ShellEX\IconHandler
        Recursive: false
        Comment: 
    -
        Description: Wow6432 ShellEx PropertySheetHandlers
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\*\ShellEx\PropertySheetHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 CLSID InprocServer32
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\InprocServer32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 CLSID InprocServer32
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\InprocServer32
        ValueName: Assembly
        Recursive: false
        Comment: 
    -
        Description: Wow6432 CLSID Instance CLSID
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\Instance
        ValueName: CLSID
        Recursive: true
        Comment: 
    -
        Description: Wow6432 CLSID Instance FriendlyName
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\Instance
        ValueName: FriendlyName
        Recursive: true
        Comment: 
    -
        Description: Wow6432 CLSID LocalServer32
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\LocalServer32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 CLSID LocalServer32
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\LocalServer32
        ValueName: Assembly
        Recursive: false
        Comment: 
    -
        Description: Wow6432 CLSID PersistentHandler
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\PersistentHandler
        Recursive: false
        Comment: 
    -
        Description: Wow6432 CLSID TypeLib
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\TypeLib
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Directory background shellex ContextMenuHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Directory\background\shellex\ContextMenuHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Directory shellex CopyHookHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Directory\shellex\CopyHookHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Directory shellex DragDropHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Directory\shellex\DragDropHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Directory shellex PropertySheetHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Directory\shellex\PropertySheetHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Drive shellex ContextMenuHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Drive\shellex\ContextMenuHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Classes Filter
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Filter
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Folder shellex ContextMenuHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Folder\shellex\ContextMenuHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Folder shellex DragDropHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Folder\shellex\DragDropHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Folder shellex PropertySheetHandlers
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Folder\shellex\PropertySheetHandlers\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Interface ProxyStubClsid32
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Interface\*\ProxyStubClsid32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Interface TypeLib
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\Interface\*\TypeLib
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 TypeLib win32
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\TypeLib\*\*\*\win32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432 TypeLib win64
        HiveType: Software
        Category: ASEP Classes
        KeyPath: Classes\Wow6432Node\TypeLib\*\*\*\win64
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: StartMenuInternet shell open command
        HiveType: Software
        Category: ASEP
        KeyPath: Clients\StartMenuInternet\*\shell\open\command
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: StartMenuInternet shell naom command
        HiveType: Software
        Category: ASEP
        KeyPath: Clients\StartMenuInternet\*\shell\naom\command
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: StartMenuInternet Shell RunAs Command
        HiveType: Software
        Category: ASEP
        KeyPath: Clients\StartMenuInternet\*\Shell\RunAs\Command
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Chrome Extensions
        HiveType: Software
        Category: ASEP
        KeyPath: Google\Chrome\Extensions
        Recursive: true
        Comment: 
    -
        Description: Google Update
        HiveType: Software
        Category: ASEP
        KeyPath: Google\Update
        ValueName: path
        Recursive: false
        Comment: 
    -
        Description: .NETFramework
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\.NETFramework
        ValueName: DbgManagedDebugger
        Recursive: false
        Comment: 
    -
        Description: Active Setup Installed Components
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Active Setup\Installed Components\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Active Setup Installed Components
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Active Setup\Installed Components\*
        ValueName: LocalizedName
        Recursive: false
        Comment: 
    -
        Description: Active Setup Installed Components
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Active Setup\Installed Components\*
        ValueName: ShellComponent
        Recursive: false
        Comment: 
    -
        Description: Active Setup Installed Components
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Active Setup\Installed Components\*
        ValueName: StubPath
        Recursive: false
        Comment: 
    -
        Description: Command Processor
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Command Processor
        ValueName: autorun
        Recursive: false
        Comment: 
    -
        Description: Cryptography Offload
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Cryptography\Offload
        ValueName: ExpoOffload
        Recursive: true
        Comment: 
    -
        Description: Ctf LangBarAddin
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Ctf\LangBarAddin
        ValueName: Filepath
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Approved Extensions
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Approved Extensions
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Explorer Bars
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Explorer Bars\*
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Extension Validation
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Extension Validation
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Extensions
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Extensions
        ValueName: ClsidExtension
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Low Rights DragDrop
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Low Rights\DragDrop
        ValueName: AppName
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Low Rights DragDrop
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Low Rights\DragDrop
        ValueName: AppPath
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Low Rights ElevationPolicy
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Low Rights\ElevationPolicy
        ValueName: AppName
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Low Rights ElevationPolicy
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Low Rights\ElevationPolicy
        ValueName: AppPath
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Low Rights ElevationPolicy
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Low Rights\ElevationPolicy
        ValueName: CLSID
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Plugins Extension
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Plugins\Extension
        Recursive: true
        Comment: 
    -
        Description: Internet Explorer Toolbar
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Toolbar
        Recursive: false
        Comment: 
    -
        Description: Internet Explorer Toolbar ShellBrowser
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Toolbar\ShellBrowser
        Recursive: false
        Comment: 
    -
        Description: Internet Explorer Toolbar WebBrowser
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\Toolbar\WebBrowser
        Recursive: false
        Comment: 
    -
        Description: Internet Explorer URLSearchHooks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Internet Explorer\URLSearchHooks
        Recursive: false
        Comment: 
    -
        Description: Office Addins
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Office\*\Addins
        ValueName: Description
        Recursive: true
        Comment: 
    -
        Description: Office Addins
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Office\*\Addins
        ValueName: FriendlyName
        Recursive: true
        Comment: 
    -
        Description: Office Addins
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Office\*\Addins
        ValueName: LoadBehavior
        Recursive: true
        Comment: 
    -
        Description: Authentication Credential Provider Filters
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Authentication Credential Providers
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\Credential Providers
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Authentication PLAP Providers
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Explorer Browser Helper Objects
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
        Recursive: true
        Comment: 
    -
        Description: Explorer FindExtensions
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\FindExtensions
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Explorer FindExtensions Static
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\FindExtensions\Static
        Recursive: true
        Comment: 
    -
        Description: Explorer SharedTaskScheduler
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
        Recursive: false
        Comment: 
    -
        Description: Explorer ShellExecuteHooks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
        Recursive: true
        Comment: 
    -
        Description: Explorer ShellIconOverlayIdentifiers
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Explorer ShellServiceObjects
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects
        ValueName: autostart
        Recursive: true
        Comment: 
    -
        Description: Ext PreApproved
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Ext\PreApproved
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Shutdown
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Startup
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup
        Recursive: true
        Comment: 
    -
        Description: Internet Settings
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Internet Settings
        ValueName: AutoConfigURL
        Recursive: false
        Comment: 
    -
        Description: Explorer Run
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment: 
    -
        Description: Policies System
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\System
        ValueName: Shell
        Recursive: false
        Comment: 
    -
        Description: Policies System
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\System
        ValueName: UIHost
        Recursive: false
        Comment: 
    -
        Description: Policies System
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\System
        ValueName: Userinit
        Recursive: false
        Comment: 
    -
        Description: Run
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: 
    -
        Description: RunOnce
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Runonce
        Recursive: false
        Comment: 
    -
        Description: RunOnce Setup
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Runonce\Setup
        Recursive: false
        Comment: 
    -
        Description: RunOnceEx
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment: 
    -
        Description: RunServices
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\RunServices
        Recursive: false
        Comment: 
    -
        Description: RunServicesOnce
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\RunServicesOnce
        Recursive: false
        Comment: 
    -
        Description: SharedDLLs
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Shareddlls
        Recursive: false
        Comment: 
    -
        Description: Shell Extensions Approved
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
        Recursive: false
        Comment: 
    -
        Description: ShellServiceObjectDelayLoad
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
        Recursive: false
        Comment: 
    -
        Description: Installed SDB
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall\*.sdb
        ValueName: InstallDate
        Recursive: true
        Comment: 
    -
        Description: Installed SDB
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall\*.sdb
        ValueName: DisplayName
        Recursive: true
        Comment: 
    -
        Description: AeDebug
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\AeDebug
        ValueName: auto
        Recursive: true
        Comment: 
    -
        Description: AeDebug
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\AeDebug
        ValueName: Debugger
        Recursive: true
        Comment: 
    -
        Description: AeDebug
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\AeDebug
        ValueName: UserDebuggerHotKey
        Recursive: true
        Comment: 
    -
        Description: AppCompatFlags Custom
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
        Recursive: true
        Comment: 
    -
        Description: AppCompatFlags InstalledSDB
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
        ValueName: DatabaseDescription
        Recursive: true
        Comment: 
    -
        Description: AppCompatFlags InstalledSDB
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
        ValueName: DatabaseInstallTimeStamp
        Recursive: true
        Comment: 
    -
        Description: AppCompatFlags InstalledSDB
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
        ValueName: DatabasePath
        Recursive: true
        Comment: 
    -
        Description: AppCompatFlags InstalledSDB
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
        ValueName: DatabaseType
        Recursive: true
        Comment: 
    -
        Description: AppCompatFlags Layers
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\Current Version\AppCompatFlags\Layers
        Recursive: false
        Comment: 
    -
        Description: Drivers
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Drivers
        Recursive: false
        Comment: 
    -
        Description: Drivers32
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Drivers32
        Recursive: false
        Comment: 
    -
        Description: Font Drivers 
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Font Drivers
        Recursive: true
        Comment: 
    -
        Description: Image File Execution Options
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Image File Execution Options
        ValueName: GlobalFlag
        Recursive: true
        Comment: 
    -
        Description: Image File Execution Options
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Image File Execution Options
        ValueName: Debugger
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Boot
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Boot
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Logon
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Maintenance
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Maintenance
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Plain
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Actions
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Author
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Description
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: DynamicInfo
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Hash
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Path
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Schema
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: SecurityDescriptor
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Source
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Triggers
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: URI
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Version
        Recursive: true
        Comment: 
    -
        Description: Schedule TaskCache Tree
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
        ValueName: Id
        Recursive: true
        Comment: 
    -
        Description: SilentProcessExit
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\SilentProcessExit
        ValueName: ReportingMode
        Recursive: true
        Comment: 
    -
        Description: SilentProcessExit
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\SilentProcessExit
        ValueName: MonitorProcess
        Recursive: true
        Comment: 
    -
        Description: Microsoft Windows NT SvcHost
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\SvcHost
        Recursive: true
        Comment: 
    -
        Description: Microsoft Windows NT Terminal Server Run
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: 
    -
        Description: Microsoft Windows NT Terminal Server Runonce
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Runonce
        Recursive: false
        Comment: 
    -
        Description: Microsoft Windows NT Terminal Server Runonceex
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Runonceex
        Recursive: false
        Comment: 
    -
        Description: Microsoft Windows NT OsImagesFolder
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Virtualization\LayerRootLocations
        Recursive: true
        Comment: Looking for OsImagesFolder.
    -
        Description: Windows NT CV Windows AppInitDlls
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: AppInit_Dlls
        Recursive: false
        Comment: 
    -
        Description: Windows NT CV Windows IconServiceLib
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: IconServiceLib
        Recursive: false
        Comment: 
    -
        Description: Windows NT CV Windows Load
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: Load
        Recursive: false
        Comment: 
    -
        Description: Windows NT CV Windows RequireSignedAppInit_DLLs
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: RequireSignedAppInit_DLLs
        Recursive: false
        Comment: 
    -
        Description: Windows NT CV Windows Run
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: Run
        Recursive: false
        Comment: 
    -
        Description: Winlogon GinaDLL
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Ginadll
        Recursive: false
        Comment: 
    -
        Description: Winlogon Userinit
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Userinit
        Recursive: false
        Comment: 
    -
        Description: Winlogon VMApplet
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: VMApplet
        Recursive: false
        Comment: 
    -
        Description: Winlogon AppSetup
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: AppSetup
        Recursive: false
        Comment: 
    -
        Description: Winlogon Shell
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Shell
        Recursive: false
        Comment: 
    -
        Description: Winlogon System
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: System
        Recursive: false
        Comment: 
    -
        Description: Winlogon Taskman
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Taskman
        Recursive: false
        Comment: 
    -
        Description: Winlogon UIHost
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: UIHost
        Recursive: false
        Comment: 
    -
        Description: Winlogon AlternateShells AvailableShells
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells
        Recursive: false
        Comment: 
    -
        Description: Winlogon GPExtensions
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Winlogon GPExtensions
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
        ValueName: DisplayName
        Recursive: true
        Comment: 
    -
        Description: Winlogon GPExtensions
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
        ValueName: dllname
        Recursive: true
        Comment: 
    -
        Description: Winlogon Notify
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
        ValueName: dllname
        Recursive: true
        Comment: 
    -
        Description: MozillaPlugins
        HiveType: Software
        Category: ASEP
        KeyPath: MozillaPlugins\*
        ValueName: path
        Recursive: false
        Comment: 
    -
        Description: Policies Scripts Logoff
        HiveType: Software
        Category: ASEP
        KeyPath: Policies\Microsoft\Windows\System\Scripts\Logoff
        ValueName: Script
        Recursive: true
        Comment: 
    -
        Description: Policies Scripts Logon
        HiveType: Software
        Category: ASEP
        KeyPath: Policies\Microsoft\Windows\System\Scripts\Logon
        ValueName: Script
        Recursive: true
        Comment: 
    -
        Description: Policies Scripts Shutdown
        HiveType: Software
        Category: ASEP
        KeyPath: Policies\Microsoft\Windows\System\Scripts\Shutdown
        ValueName: Script
        Recursive: true
        Comment: 
    -
        Description: Policies Scripts Startup
        HiveType: Software
        Category: ASEP
        KeyPath: Policies\Microsoft\Windows\System\Scripts\Startup
        ValueName: Script
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Google Update
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Google\Update
        ValueName: path
        Recursive: false
        Comment: 
    -
        Description: WOW6432 .NETFramework
        HiveType: Software
        Category: ASEP
        KeyPath: WOW6432Node\Microsoft\.NETFramework
        ValueName: DbgManagedDebugger
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Active Setup Installed Components
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Active Setup\Installed Components\*
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Active Setup Installed Components
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Active Setup\Installed Components\*
        ValueName: ShellComponent
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Active Setup Installed Components
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Active Setup\Installed Components\*
        ValueName: StubPath
        Recursive: true
        Comment: 
    -
        Description: WOW6432 Command Processor Autorun
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Command Processor
        ValueName: Autorun
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Ctf LangBarAddin
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Ctf\LangBarAddin
        ValueName: Filepath
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Approved Extensions
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Approved Extensions
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Explorer Bars
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Explorer Bars\*
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Extension Validation
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Extension Validation
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Extensions
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Extensions
        ValueName: ClsidExtension
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Low Rights DragDrop
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Low Rights\DragDrop
        ValueName: AppName
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Low Rights DragDrop
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Low Rights\DragDrop
        ValueName: AppPath
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Low Rights ElevationPolicy AppName
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy
        ValueName: AppName
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Low Rights ElevationPolicy AppPath
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy
        ValueName: AppPath
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Low Rights ElevationPolicy CLSID
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy
        ValueName: CLSID
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Plugins Extension
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Plugins\Extension
        Recursive: true
        Comment: 
    -
        Description: Wow6432 IE Toolbar
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Toolbar
        Recursive: false
        Comment: 
    -
        Description: Wow6432 IE Toolbar ShellBrowser
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Toolbar\ShellBrowser
        Recursive: false
        Comment: 
    -
        Description: Wow6432 IE Toolbar WebBrowser
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\Toolbar\WebBrowser
        Recursive: false
        Comment: 
    -
        Description: Wow6432 IE URLSearchHooks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Internet Explorer\URLSearchHooks
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Office Addins
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Office\*\Addins
        ValueName: Description
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Office Addins
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Office\*\Addins
        ValueName: FriendlyName
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Office Addins
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Office\*\Addins
        ValueName: LoadBehavior
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Authentication Credential Provider Filters
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Authentication Credential Providers
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Authentication PLAP Providers
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Explorer Browser Helper Objects
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Explorer FindExtensions
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FindExtensions
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Explorer FindExtensions Static
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FindExtensions\Static
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Explorer SharedTaskScheduler
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Explorer ShellExecuteHooks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Explorer ShellIconOverlayIdentifiers
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Explorer ShellServiceObjects
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects
        ValueName: autostart
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Ext PreApproved
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Ext\PreApproved
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Internet Settings
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings
        ValueName: AutoConfigURL
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Run
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: 
    -
        Description: Wow6432 RunOnce
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Runonce
        Recursive: false
        Comment: 
    -
        Description: Wow6432 RunOnce Setup
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Runonce\Setup
        Recursive: false
        Comment: 
    -
        Description: Wow6432 RunOnceEx
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment: 
    -
        Description: Wow6432 RunServices
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
        Recursive: false
        Comment: 
    -
        Description: Wow6432 RunServicesOnce
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
        Recursive: false
        Comment: 
    -
        Description: Wow6432 SharedDLLs
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Shareddlls
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Shell Extensions Approved
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
        Recursive: false
        Comment: 
    -
        Description: Wow6432 ShellServiceObjectDelayLoad
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Installed SDB
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*.sdb
        ValueName: InstallDate
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Installed SDB
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*.sdb
        ValueName: DisplayName
        Recursive: true
        Comment: 
    -
        Description: Wow6432 AeDebug
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug
        ValueName: auto
        Recursive: true
        Comment: 
    -
        Description: Wow6432 AeDebug
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug
        ValueName: Debugger
        Recursive: true
        Comment: 
    -
        Description: Wow6432 AeDebug
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug
        ValueName: UserDebuggerHotKey
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
        Recursive: true
        Comment: 
    -
        Description: Wow6432 AppCompatFlags InstalledSDB
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
        ValueName: DatabaseDescription
        Recursive: true
        Comment: 
    -
        Description: Wow6432 AppCompatFlags InstalledSDB
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
        ValueName: DatabaseInstallTimeStamp
        Recursive: true
        Comment: 
    -
        Description: Wow6432 AppCompatFlags InstalledSDB
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
        ValueName: DatabasePath
        Recursive: true
        Comment: 
    -
        Description: Wow6432 AppCompatFlags InstalledSDB
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
        ValueName: DatabaseType
        Recursive: true
        Comment: 
    -
        Description: Wow6432 AppCompatFlags Layers
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\Current Version\AppCompatFlags\Layers
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Drivers
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Drivers32
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Font Drivers 
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Image File Execution Options
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
        ValueName: GlobalFlag
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Image File Execution Options
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
        ValueName: Debugger
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Boot
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Boot
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Logon
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Maintenance
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Maintenance
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Plain
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Actions
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Author
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Description
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: DynamicInfo
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Hash
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Path
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Schema
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: SecurityDescriptor
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Source
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Triggers
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: URI
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tasks
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
        ValueName: Version
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Schedule TaskCache Tree
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
        ValueName: Id
        Recursive: true
        Comment: 
    -
        Description: Wow6432 SilentProcessExit
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit
        ValueName: ReportingMode
        Recursive: true
        Comment: 
    -
        Description: Wow6432 SilentProcessExit
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit
        ValueName: MonitorProcess
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Microsoft Windows NT SvcHost
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\SvcHost
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Microsoft Windows NT Terminal Server Run
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Microsoft Windows NT Terminal Server Runonce
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Runonce
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Microsoft Windows NT Terminal Server Runonceex
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Runonceex
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Microsoft Windows NT OsImagesFolder
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Virtualization\LayerRootLocations
        Recursive: true
        Comment: Looking for OsImagesFolder.
    -
        Description: Wow6432 Microsoft Windows NT CurrentVersion Windows
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: AppInit_Dlls
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Windows NT CV Windows IconServiceLib
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: IconServiceLib
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Windows NT CV Windows Load
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: Load
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Windows NT CV Windows RequireSignedAppInit_DLLs
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: RequireSignedAppInit_DLLs
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Windows NT CV Windows Run
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: Run
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon GinaDLL
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Ginadll
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon Userinit
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Userinit
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon VMApplet
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: VMApplet
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon AppSetup
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: AppSetup
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon Shell
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Shell
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon System
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: System
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon Taskman
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Taskman
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon UIHost
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: UIHost
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon AlternateShells AvailableShells
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Winlogon GPExtensions
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Winlogon GPExtensions
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
        ValueName: DisplayName
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Winlogon GPExtensions
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
        ValueName: dllname
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Winlogon Notify
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
        ValueName: dllname
        Recursive: true
        Comment: 
    -
        Description: Wow6432 MozillaPlugins
        HiveType: Software
        Category: ASEP
        KeyPath: Wow6432Node\MozillaPlugins\*
        ValueName: path
        Recursive: false
        Comment: 
    -
        Description: Desktop Wallpaper
        HiveType: ntuser
        Category: ASEP
        KeyPath: Control Panel\DeskTop
        ValueName: ConvertedWallpaper
        Recursive: false
        Comment: 
    -
        Description: Desktop Wallpaper
        HiveType: ntuser
        Category: ASEP
        KeyPath: Control Panel\DeskTop
        ValueName: OriginalWallpaper
        Recursive: false
        Comment: 
    -
        Description: Desktop Wallpaper
        HiveType: ntuser
        Category: ASEP
        KeyPath: Control Panel\DeskTop
        ValueName: WallPaper
        Recursive: false
        Comment: 
    -
        Description: Desktop Screensaver
        HiveType: ntuser
        Category: ASEP
        KeyPath: Control Panel\DeskTop
        ValueName: scrnsave.exe
        Recursive: false
        Comment: 
    -
        Description: Environment Logon Script
        HiveType: ntuser
        Category: ASEP
        KeyPath: Environment
        ValueName: UserInitMprLogonScript
        Recursive: false
        Comment: 
    -
        Description: Chrome Extensions
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Google\Chrome\Extensions
        ValueName: path
        Recursive: true
        Comment: 
    -
        Description: Active Setup
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Active Setup\Installed Components
        Recursive: true
        Comment: 
    -
        Description: Command Processor
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Command Processor
        ValueName: autorun
        Recursive: false
        Comment: 
    -
        Description: Ctf LangBarAddin
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Ctf
        ValueName: LangBarAddin
        Recursive: false
        Comment: 
    -
        Description: IE Approved Extensions
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\Approved Extensions
        Recursive: false
        Comment: 
    -
        Description: IE DeskTop Components
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\DeskTop\Components
        Recursive: true
        Comment: 
    -
        Description: IE BackupWallpaper
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\Desktop\General
        ValueName: BackupWallpaper
        Recursive: false
        Comment: 
    -
        Description: IE wallpapersource
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\Desktop\General
        ValueName: wallpapersource
        Recursive: false
        Comment: 
    -
        Description: IE Explorer Bars
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\Explorer Bars
        Recursive: true
        Comment: 
    -
        Description: IE Extension Validation
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\Extension Validation
        Recursive: true
        Comment: 
    -
        Description: IE Extensions
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\Extensions
        Recursive: true
        Comment: 
    -
        Description: IE MenuExt
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\MenuExt
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: IE Toolbar ShellBrowser
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\Toolbar\ShellBrowser
        Recursive: false
        Comment: 
    -
        Description: IE Toolbar WebBrowser
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\Toolbar\WebBrowser
        Recursive: false
        Comment: 
    -
        Description: IE URLSearchHooks
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Internet Explorer\URLSearchHooks
        Recursive: false
        Comment: 
    -
        Description: Office Addins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Office\*\Addins
        Recursive: false
        Comment: 
    -
        Description: Office Addins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Office\*\Addins\*
        Recursive: false
        Comment: 
    -
        Description: Explorer Browser Helper Objects
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
        Recursive: true
        Comment: 
    -
        Description: Explorer SharedTaskScheduler
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
        Recursive: true
        Comment: 
    -
        Description: Explorer ShellIconOverlayIdentifiers
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers
        Recursive: true
        Comment: 
    -
        Description: Explorer ShellServiceObjects
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects
        Recursive: true
        Comment: 
    -
        Description: Ext Settings
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Ext\Settings
        Recursive: true
        Comment: 
    -
        Description: Ext Stats
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Ext\Stats
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: DisplayName
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: ExecTime
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: FileSysPath
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: GPO-ID
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: IsPowershell
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: Parameters
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: PSScriptOrder
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: Script
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logoff
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*
        ValueName: SOM-ID
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: DisplayName
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: ExecTime
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: FileSysPath
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: GPO-ID
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon*
        ValueName: IsPowershell
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: Parameters
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: PSScriptOrder
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: Script
        Recursive: true
        Comment: 
    -
        Description: Group Policy Scripts Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: SOM-ID
        Recursive: true
        Comment: 
    -
        Description: Internet Settings AutoConfigProxy
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Internet Settings
        ValueName: AutoConfigProxy
        Recursive: false
        Comment: 
    -
        Description: Internet Settings AutoConfigURL
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Internet Settings
        ValueName: AutoConfigURL
        Recursive: false
        Comment: 
    -
        Description: Policies Explorer NoDriveTypeAutoRun
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
        ValueName: NoDriveTypeAutoRun
        Recursive: false
        Comment: 
    -
        Description: Policies Explorer Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment: 
    -
        Description: Policies System Shell
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Policies\System
        ValueName: Shell
        Recursive: false
        Comment: 
    -
        Description: Policies System
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Policies\System
        ValueName: UserInit
        Recursive: false
        Comment: 
    -
        Description: Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: 
    -
        Description: RunOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: 
    -
        Description: RunOnceEx
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment: 
    -
        Description: RunServices
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunServices
        Recursive: false
        Comment: 
    -
        Description: RunServicesOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
        Recursive: false
        Comment: 
    -
        Description: Shell Extensions Approved
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
        Recursive: true
        Comment: 
    -
        Description: ShellServiceObjectDelayLoad
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
        Recursive: true
        Comment: 
    -
        Description: Drivers
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\drivers
        Recursive: false
        Comment: 
    -
        Description: Drivers32
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\drivers32
        Recursive: false
        Comment: 
    -
        Description: Terminal Server Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: 
    -
        Description: Terminal Server RunOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: 
    -
        Description: Terminal Server RunOnceEx
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment: 
    -
        Description: Load
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: Load
        Recursive: false
        Comment: 
    -
        Description: Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: Run
        Recursive: false
        Comment: 
    -
        Description: Winlogon Shell
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: Shell
        Recursive: false
        Comment: 
    -
        Description: Winlogon Userinit
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: userinit
        Recursive: false
        Comment: 
    -
        Description: Winlogon VMapplet
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: VMapplet
        Recursive: false
        Comment: 
    -
        Description: Mozilla Components, Extensions, & Plugins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Mozilla\*\Components
        Recursive: true
        Comment: 
    -
        Description: Mozilla Components, Extensions, & Plugins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Mozilla\*\Extensions\Components
        Recursive: true
        Comment: 
    -
        Description: Mozilla Components, Extensions, & Plugins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Mozilla\*\Extensions\Plugins
        Recursive: true
        Comment: 
    -
        Description: Mozilla Components, Extensions, & Plugins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Mozilla\*\Plugins
        Recursive: true
        Comment: 
    -
        Description: Mozilla Components, Extensions, & Plugins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\MozillaPlugins
        Recursive: true
        Comment: 
    -
        Description: Policies Desktop Screensaver
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Policies\Microsoft\Windows\Control Panel\Desktop
        ValueName: Scrnsave.exe
        Recursive: false
        Comment: 
    -
        Description: Policies Logoff Script
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Policies\Microsoft\Windows\System\Scripts\Logoff
        ValueName: Script
        Recursive: true
        Comment: 
    -
        Description: Policies Logon Script
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Policies\Microsoft\Windows\System\Scripts\Logon
        ValueName: Script
        Recursive: true
        Comment: 
    -
        Description: Domain Profile Authorized Applications
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AuthorizedApplications
        Recursive: true
        Comment: 
    -
        Description: Standard Profile Authorized Applications
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Policies\Microsoft\WindowsFirewall\StandardProfile\AuthorizedApplications
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Active Setup
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Active Setup\Installed Components
        Recursive: true
        Comment: 
    -
        Description: Wow6432 Command Processor
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Command Processor
        ValueName: autorun
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Internet Explorer Explorer Bars
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Internet Explorer\Explorer Bars
        Recursive: false
        Comment: 
    -
        Description: Wow6432 Internet Explorer Extension
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Internet Explorer\Extension
        Recursive: false
        Comment: 
    -
        Description: WOW6432Node Office Addins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Office\*\Addins
        Recursive: false
        Comment: 
    -
        Description: WOW6432Node Office Addins
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Office\*\Addins\*
        Recursive: false
        Comment: 
    -
        Description: WOW6432Node Drivers32
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
        Recursive: true
        Comment: 
    -
        Description: WOW6432Node Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: 
    -
        Description: WOW6432Node RunOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: 
    -
        Description: .cmd
        HiveType: usrclass
        Category: ASEP
        KeyPath: .cmd
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: .cmd PersistentHandler
        HiveType: usrclass
        Category: ASEP
        KeyPath: .cmd\PersistentHandler
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: .exe
        HiveType: usrclass
        Category: ASEP
        KeyPath: .exe
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: .exe PersistentHandler
        HiveType: usrclass
        Category: ASEP
        KeyPath: .exe\PersistentHandler
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: cmdfile
        HiveType: usrclass
        Category: ASEP
        KeyPath: cmdfile
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: exefile
        HiveType: usrclass
        Category: ASEP
        KeyPath: exefile
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Htmlfile Open
        HiveType: usrclass
        Category: ASEP
        KeyPath: Htmlfile\Shell\Open\Command
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx ColumnHandlers
        HiveType: usrclass
        Category: ASEP
        KeyPath: '*\ShellEx\ColumnHandlers'
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx ContextMenuHandlers
        HiveType: usrclass
        Category: ASEP
        KeyPath: '*\ShellEx\ContextMenuHandlers'
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx CopyHookHandlers
        HiveType: usrclass
        Category: ASEP
        KeyPath: '*\ShellEx\CopyHookHandlers'
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx DragDropHandlers
        HiveType: usrclass
        Category: ASEP
        KeyPath: '*\ShellEx\DragDropHandlers'
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx ExtShellFolderViews
        HiveType: usrclass
        Category: ASEP
        KeyPath: '*\ShellEx\ExtShellFolderViews'
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: ShellEx PropertySheetHandlers
        HiveType: usrclass
        Category: ASEP
        KeyPath: '*\ShellEx\PropertySheetHandlers'
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Directory Background ContextMenuHandlers
        HiveType: usrclass
        Category: ASEP
        KeyPath: Directory\Background\ShellEx\ContextMenuHandlers
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: CLSID InprocServer32
        HiveType: usrclass
        Category: ASEP
        KeyPath: CLSID\*\InprocServer32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: CLSID InprocServer32
        HiveType: usrclass
        Category: ASEP
        KeyPath: CLSID\*\InprocServer32
        ValueName: Assembly
        Recursive: false
        Comment: 
    -
        Description: CLSID LocalServer32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: CLSID\*\LocalServer32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: CLSID LocalServer32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: CLSID\*\LocalServer32
        ValueName: Assembly
        Recursive: false
        Comment: 
    -
        Description: CLSID PersistentHandler
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: CLSID\*\PersistentHandler
        Recursive: false
        Comment: 
    -
        Description: CLSID TypeLib
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: CLSID\*\TypeLib
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: CLSID Instance CLSID
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: CLSID\*\Instance
        ValueName: CLSID
        Recursive: true
        Comment: 
    -
        Description: CLSID Instance FriendlyName
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: CLSID\*\Instance
        ValueName: FriendlyName
        Recursive: true
        Comment: 
    -
        Description: Interface ProxyStubClsid32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Interface\*\ProxyStubClsid32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Protocols CLSID
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Protocols\Filter\*
        ValueName: CLSID
        Recursive: false
        Comment: 
    -
        Description: Protocols Handler
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Protocols\Handler\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Protocols Handler CLSID
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Protocols\Handler\*
        ValueName: CLSID
        Recursive: false
        Comment: 
    -
        Description: Protocols Name-Space Handler
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Protocols\Name-Space Handler\*
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: ProtocolsName-Space Handler CLSID
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Protocols\Name-Space Handler\*
        ValueName: CLSID
        Recursive: true
        Comment: 
    -
        Description: TypeLib
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: TypeLib\*\*
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: TypeLib Win32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: TypeLib\*\*\*\win32
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: TypeLib Win64
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: TypeLib{*\*\*\win64
        ValueName: (default)
        Recursive: true
        Comment: 
    -
        Description: Wow6432Node CLSID InprocServer32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\InprocServer32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432Node CLSID InprocServer32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\InprocServer32
        ValueName: Assembly
        Recursive: false
        Comment: 
    -
        Description: Wow6432Node CLSID LocalServer32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\LocalServer32
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432Node CLSID LocalServer32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\LocalServer32
        ValueName: Assembly
        Recursive: false
        Comment: 
    -
        Description: Wow6432Node CLSID PersistentHandler
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\PersistentHandler
        Recursive: false
        Comment: 
    -
        Description: Wow6432Node CLSID TypeLib
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\TypeLib
        ValueName: (default)
        Recursive: false
        Comment: 
    -
        Description: Wow6432Node CLSID Instance CLSID
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\Instance
        ValueName: CLSID
        Recursive: true
        Comment: 
    -
        Description: Wow6432Node CLSID Instance FriendlyName
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\Instance
        ValueName: FriendlyName
        Recursive: true
        Comment: 
    -
        Description: Wow6432Node Interface ProxyStubClsid32
        HiveType: USRCLASS
        Category: ASEP
        KeyPath: Wow6432Node\Interface\*\ProxyStubClsid32
        ValueName: (default)
        Recursive: false
        Comment: 
