Description: TrustedDocuments - RECmd batch file
Author: Martin Willing
Version: 1
Id: ab13eb5f-31db-5cdc-83df-81ec83dc15
Keys:
    -
        Description: This registry key contains a list of Microsoft Office document file locations for which a user has explicitly enabled editing and macros.
        HiveType: NTUSER
        Category: Office Documents
        KeyPath: Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords
        Recursive: true