Description: LastVisitedMRU - RECmd batch file
Author: Martin Willing
Version: 1
Id: ab16eb5f-31db-5cdc-83df-88ec83d61b
Keys:
    -
        Description: LastVisitedPidlMRU
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        Recursive: false
        Comment: "Tracks the specific executable used by an application to open the files documented in OpenSavePidlMRU"