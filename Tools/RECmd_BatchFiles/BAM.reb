Description: BAM/DAM - RECmd batch file
Author: Martin Willing
Version: 1
Id: ab13eb6f-31db-5cdc-83df-88ec86dc17
Keys:
    -
        Description: Windows Background Activity Moderator (BAM)
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet*\Services\bam\State\UserSettings\*
        Recursive: false
    -
        Description: Windows Background Activity Moderator (BAM)
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet*\Services\bam\UserSettings\*
        Recursive: false
    -
        Description: Windows Desktop Activity Moderator (DAM)
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet*\Services\dam\State\UserSettings\*
        Recursive: false
    -
        Description: Windows Desktop Activity Moderator (DAM)
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet*\Services\dam\UserSettings\*
        Recursive: false