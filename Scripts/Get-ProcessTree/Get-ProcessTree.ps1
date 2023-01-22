<#
.SYNOPSIS
    Shows a process history tree with data extracted from a MemProcFS-Analyzer process overview CSV
.EXAMPLE
    PS> Get-ProcessTree.ps1 -CSVPath "~\Desktop\proc.csv"
    Shows the process tree using data from the given CSV
.AUTHOR
	Dominik Schmidt @ https://github.com/DaFuqs
.VERSION
    1.4
.VERSION_HISTORY
    1.4: - Nodes to not expand / subtract on double click anymore. This action is already used for opening the properties window
    1.3: - Use a compiled version of DamerauLevenshteinDistance for increased performance
         - Orphaned processes get that listed in the "Suspicious" tag
         - New Switch Param: NoSuspiciousChecks: for when you just want a quick process tree without automatic checks for suspicious entries
         - Right click menu for the popup process properties window to copy selected/all values
    1.2: - Fixed hang when pid<=>parent PPIDs result in a ppid loop (like when PIDs have been reused). Findings will be reported
         - 4 new process masquerading checks:
             - processes with unusual parents
             - processes in unusual paths
             - processes with an unusual number of instances
             - similarly named processes to known-good ones
    1.1: - Double Clicking an Entry brings up a property view
         - Suspicious Entries get colored red and list their suspicion hits in their tooltip + properties view
    1.0: Public release
#>

[CmdletBinding()]

Param (
    # Path to the input CSV file
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	[ValidateScript({try { Test-Path -Path $_ -PathType Leaf } catch { throw "No file at `"$_`"" }})] # test if there is a file at given location
    [string] $CSVPath = ".\proc.csv",
    
    # Process names of script interpreters
    # Will be matched 1:1
    [Parameter(Mandatory=$false)]
    $ScriptInterpreters = @("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "python.exe"),

    [Parameter(Mandatory=$false)]
    $LateralMovementPrograms =  @("*psexec*", "mstsc.exe", "putty.exe", "winscp.exe", "scp.exe"),

    # https://attack.mitre.org/techniques/T1218/
    [Parameter(Mandatory=$false)]
    $SuspiciousPrograms =  @("*certutil.exe", "ping.exe", "msconfig.exe", "nslookup.exe", "ipconfig.exe", "systeminfo.exe", "nltest.exe", "net.exe", "chcp.exe", "bitsadmin.exe", "WSreset.exe", "mshta.exe", 
    "regsvr32.exe", "rundll32.exe", "mavinject.exe", "sc.exe", "tasklist.exe", 
    "msbuild.exe" # https://attack.mitre.org/techniques/T1127/001/
    "adfind.exe" # https://attack.mitre.org/techniques/T1087/002/
    ),

    # 
    [Parameter(Mandatory=$false)]
    $SuspiciousParameters = @(
        [Tuple]::Create("powershell.exe", "-Enc")
        [Tuple]::Create("powershell.exe", "Webclient")
        [Tuple]::Create("powershell.exe", "Hidden")  # T1564.003
        [Tuple]::Create("powershell.exe", "Bypass")
        [Tuple]::Create("wscript.exe", "PubPrn") # https://attack.mitre.org/techniques/T1216/001/
        [Tuple]::Create("cscript.exe", "PubPrn") # https://attack.mitre.org/techniques/T1216/001
    ),

    #  [T1036.007]
    $DoubleFileExtensions,

    # Names of folders where process launch should be noted as suspicious
    # Will be matched via -like (use * as wildcard at start and end)
    [Parameter(Mandatory=$false)]
    $SuspiciousFolders =  @("*\appdata\*", "*\temp\*"),

    # Parent Process Name => File Path
    # Process names will be matched 1:1
    # File Paths will be matched via -like (use * as wildcard at start and end)
    [Parameter(Mandatory=$false)]
    $UnusualRelationships = @(
        [Tuple]::Create("Excel.exe", "*.exe")
        [Tuple]::Create("Word.exe", "*.exe")
        [Tuple]::Create("Outlook.exe", "*.exe")
        [Tuple]::Create("MSEdge.exe", "*.exe")
        [Tuple]::Create("Chrome.exe", "*.exe")
        [Tuple]::Create("Firefox.exe", "*.exe")
        [Tuple]::Create("Schtasks.exe", "powershell.exe")
        [Tuple]::Create("Schtasks.exe", "cmd.exe")
        [Tuple]::Create("Schtasks.exe", "C:\Users\*")
        [Tuple]::Create("Schtasks.exe", "C:\ProgramData\*")
        [Tuple]::Create("Schtasks.exe", "rundll32.exe")
        [Tuple]::Create("userinit.exe", "*exp*")
        [Tuple]::Create("powershell.exe", "*")
        [Tuple]::Create("WMIPrvSE.exe", "*")
        [Tuple]::Create("rundll32.exe", "C:\Users\*")
    ),

    # Known windows processes and their usual parents
    [Parameter(Mandatory=$false)]
    $ExpectedRelationships = @{
        "csrss.exe" = @("smss.exe", "svchost.exe")
        "LogonUI.exe" = @("wininit.exe", "winlogon.exe")
        "lsass.exe" = @("wininit.exe")
        "services.exe" = @("wininit.exe")
        "smss.exe" = @("System", "smss.exe")
        "spoolsv.exe" = @("services.exe")
        "svchost.exe" = @("services.exe", "MsMpEng.exe", "svchost.exe")
        "taskhost.exe" = @("services.exe", "svchost.exe")
        "taskhostw.exe" = @("services.exe", "svchost.exe")
        "userinit.exe" = @("dwm.exe", "winlogon.exe")
        "wininit.exe" = @("smss.exe")
        "winlogon.exe" = @("smss.exe")
    },

    # They will be matched using regex
    [Parameter(Mandatory=$false)]
    $ExpectedProcessPaths = @{
        "csrss.exe" = "\\Windows\\System32\\csrss\.exe"
        "explorer.exe" = "\\Windows\\explorer\.exe"
        "lsass.exe" = "\\Windows\\System32\\lsass\.exe"
        "lsm.exe" = "\\Windows\\System32\\lsm\.exe"
        "services.exe" = "\\Windows\\System32\\services\.exe"
        "smss.exe" = "\\Windows\\System32\\smss\.exe"
        "svchost.exe" = "\\Windows\\(System32)?(SysWOW64)?\\svchost\.exe"
        "taskhost.exe" = "\\Windows\\System32\\taskhost\.exe"
        "taskhostw.exe" = "\\Windows\\System32\\taskhostw\.exe"
        "wininit.exe" = "\\Windows\\System32\\wininit\.exe"
        "winlogon.exe" = "\\Windows\\System32\\winlogon\.exe"
    },

    [Parameter(Mandatory=$false)]
    $ExpectedProcessInstanceCounts = @{
        "lsaiso.exe" = 1
        "lsass.exe" = 1
        "lsm.exe" = 1
        "services.exe" = 1
        "wininit.exe" = 1
    },

    [Parameter(Mandatory=$false)]
    $ProcessesToSearchSimilarNames = @("csrss.exe", "dllhost.exe", "explorer.exe", "iexplore.exe", "lsass.exe", "sihost.exe", "smss.exe", "svchost.exe", "winlogon.exe"),

    # Directly display not only process names, but also PIDs
    [Parameter(Mandatory=$false)]
    [switch] $VisualPIDs = $true,
    
    # Skips all checks of suspicous entries, making the GUI display much faster
    [Parameter(Mandatory=$false)]
    [switch] $NoSuspiciousChecks
)

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void][System.Reflection.Assembly]::LoadWithPartialName("PresentationFramework")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows")


# querying the entries of the csv file
$csvEntries = @(Import-CSV -Path $CSVPath -Delimiter "`t")


####################################
#region    DOTNET-SHENANIGANS      #
####################################


try {
    [LevenshteinDistance]::new() -as [Type] | Out-Null
} catch {
    Add-Type -Path (Join-Path $PSScriptRoot -ChildPath "..\Measure-DamerauLevenshteinDistance\Measure-DamerauLevenshteinDistance.cs") | Out-Null
}


# Fuse of
# https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.treeview.treeviewnodesorter
# https://www.dotnetperls.com/alphanumeric-sorting
try {
    [TreeNodeAlphanumComparator] -as [Type] | Out-Null
} catch {
    Add-Type @"
using System;
using System.Collections;
using System.Windows.Forms;
public class TreeNodeAlphanumComparator : IComparer {
    public int Compare(object x, object y) {
        TreeNode tx = x as TreeNode;
        TreeNode ty = y as TreeNode;
        if (tx == null) {
            return 0;
        }
        if (ty == null) {
            return 0;
        }
        string s1 = tx.Text;
        if (s1 == null) {
            return 0;
        }
        string s2 = ty.Text;
        if (s2 == null) {
            return 0;
        }
        
        int len1 = s1.Length;
        int len2 = s2.Length;
        int marker1 = 0;
        int marker2 = 0;
        
        // Walk through two the strings with two markers.
        while (marker1 < len1 && marker2 < len2) {
            char ch1 = s1[marker1];
            char ch2 = s2[marker2];
            
            // Some buffers we can build up characters in for each chunk.
            char[] space1 = new char[len1];
            int loc1 = 0;
            char[] space2 = new char[len2];
            int loc2 = 0;
            
            // Walk through all following characters that are digits or
            // characters in BOTH strings starting at the appropriate marker.
            // Collect char arrays.
            do {
                space1[loc1++] = ch1;
                marker1++;
                
                if (marker1 < len1) {
                    ch1 = s1[marker1];
                } else {
                    break;
                }
            } while (char.IsDigit(ch1) == char.IsDigit(space1[0]));
            
            do {
                space2[loc2++] = ch2;
                marker2++;
                
                if (marker2 < len2) {
                    ch2 = s2[marker2];
                } else {
                    break;
                }
            } while (char.IsDigit(ch2) == char.IsDigit(space2[0]));
            
            // If we have collected numbers, compare them numerically.
            // Otherwise, if we have strings, compare them alphabetically.
            string str1 = new string(space1);
            string str2 = new string(space2);
            
            int result;
            
            if (char.IsDigit(space1[0]) && char.IsDigit(space2[0])) {
                int thisNumericChunk = int.Parse(str1);
                int thatNumericChunk = int.Parse(str2);
                result = thisNumericChunk.CompareTo(thatNumericChunk);
            } else {
                result = str1.CompareTo(str2);
            }
            
            if (result != 0) {
                return result;
            }
        }
        return len1 - len2;
    }
}
"@ -ReferencedAssemblies System.Windows.Forms | Out-Null
}

####################################
#endregion DOTNET-SHENANIGANS      #
####################################


####################################
#region    HELPER FUNCTIONS        #
####################################

# huge thanks to
# https://nasbench.medium.com/demystifying-the-svchost-exe-process-and-its-command-line-options-508e9114e747
# for the great writeup!
function Get-SVCHostData($k, $s) {
    $values = @((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\").$k)
    if($s) {
        if($values -contains($s)) {
            return "[$s]"
        } else {
            return "[???]"
        }
    }
    return "[" + ($values -join ", ") + "]"
}

function Is-Match($Text, $SearchText, $SearchMode) {
    if($searchMode -eq 0) { # plaintext
        if($text -and $Text.toLower().Contains($SearchText.toLower())) {
            return $true
        }
    } elseif($searchMode -eq 1) { # extended
        if($Text -like $SearchText) {
            return $true
        }
    } else { # regex
        if($Text -match $SearchText) {
            return $true
        }
    }
    $false
}

function Show-EntryWindow($entry) {
    # create form for displaying the folder tree
    $entryForm = New-Object System.Windows.Forms.Form
    $entryForm.Text = $entry."Process Name" + ": " + $entry.PID + " - Properties"
    $entryForm.Size = New-Object System.Drawing.Size(500, 395)
    $entryForm.Icon = $icon

    $alternateCellStyle = New-Object System.Windows.Forms.DataGridViewCellStyle
    $alternateCellStyle.BackColor = [System.Drawing.SystemColors]::ControlLight
    
    $script:dataGridView = New-Object System.Windows.Forms.DataGridView
    $dataGridView.Name = "EntryPropertiesGridView"
    $dataGridView.AllowUserToAddRows = $false
    $dataGridView.AllowUserToDeleteRows = $false
    $dataGridView.AllowUserToOrderColumns = $false
    $dataGridView.AllowUserToResizeRows = $false
    $dataGridView.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing
    $dataGridView.RowHeadersVisible = $false
    $dataGridView.ReadOnly = $true
    $dataGridView.ColumnCount = 2
    $dataGridView.Columns[0].Name = "Property"
    $dataGridView.Columns[0].AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
    $dataGridView.Columns[1].Name = "Value"
    $dataGridView.Columns[1].AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    $dataGridView.AlternatingRowsDefaultCellStyle = $alternateCellStyle
    $dataGridView.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $dataGridView.Dock = [System.Windows.Forms.DockStyle]::Fill

    $contextMenuStrip = New-Object System.Windows.Forms.ContextMenuStrip
    $contextMenuStrip.Items.Add("Copy highlighted rows").add_Click({
        $sb = New-Object System.Text.StringBuilder
        foreach($row in $dataGridView.SelectedRows) {
            $sb.AppendLine($row.Cells[0].Value + " " + $row.Cells[1].Value)
        }
        [System.Windows.Forms.Clipboard]::SetText($sb.ToString())
    })
    $contextMenuStrip.Items.Add("Copy all rows").add_Click({
        $sb = New-Object System.Text.StringBuilder
        foreach($row in $dataGridView.Rows) {
            $sb.AppendLine($row.Cells[0].Value + " " + $row.Cells[1].Value)
        }
        [System.Windows.Forms.Clipboard]::SetText($sb.ToString())
    })
    $dataGridView.ContextMenuStrip = $contextMenuStrip

    foreach($property in $entry.psobject.Properties) {
        $dataGridView.Rows.Add($property.Name + ":", $property.Value)
    }

    $entryForm.BackColor = [System.Drawing.SystemColors]::ControlLight
    $entryForm.Controls.Add($dataGridView)
    $entryForm.Show()
}

function Note-Suspicious($Node, $Description) {
    if($Node.Tag.Suspicious) {
        $Node.Tag.Suspicious = $Node.Tag.Suspicious + ", " + $Description
    } else {
        $Node.Tag.Suspicious = $Description
    }
    $Node.ForeColor = [System.Drawing.Color]::Red
    $Node.ToolTipText = ($Node.Tag | Out-String).Trim() -replace " *:", ":"
}

function Set-Suspicious($Node, $ParentID, $Description, $ShortId) {
    Note-Suspicious -Node $node -Description $Description
    New-Node -ID $($Node.Tag.PID + "_" + $ShortId) -Text $process."Call Chain" -Tooltip $node.ToolTipText -Parent $ParentID -Tag $Node.Tag
}

####################################
#endregion HELPER FUNCTIONS        #
####################################


####################################
#region    GUI                     #
####################################

# create form for displaying the folder tree
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "MemProcFS-Analyzer - Process Tree"
$Form.Size = New-Object System.Drawing.Size(800, 600)

# the icon (base 64 encoded png, converted and set as icon)
$base64Icon = "iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAABmJLR0QAAAAAAAD5Q7t/AAAACXBIWXMAAABgAAAAYADwa0LPAAAAxElEQVRIx+3TsWoCQRCA4Y8kNkklnCRVEB/gGh/ZB8gTCJo6zYGtiJ0vYH0pMsJiItzpRBt/WLid5f6Znd3lzq15TPY94wM7bLKLfcESLVZ4uEQ2xiykx/JNrP+i7TAOLGK+xGsXed8E45C12HeRn8M71iHfYpIpL3eyyK78KtT4xFsRG8VuphkJ5n5636CK0URsnpGgFDZH39Wpn/pcUxjiq1j7U37Jc37CoJgPIpbCWS3qw78fch2istoqYnVWm+7k8A1FT08gOQfCGwAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyMi0wOS0wNVQxMjoyMTozMSswMDowMOTTZSwAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjItMDktMDVUMTI6MjE6MzErMDA6MDCVjt2QAAAAAElFTkSuQmCC"
$bitmap = New-Object System.Windows.Media.Imaging.BitmapImage
$bitmap.BeginInit()
$bitmap.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($base64Icon)
$bitmap.EndInit()
$bitmap.Freeze()
$image = [System.Drawing.Bitmap][System.Drawing.Image]::FromStream($bitmap.StreamSource)
$icon = [System.Drawing.Icon]::FromHandle($image.GetHicon())
$Form.Icon = $icon

# the main tree
$TreeView = New-Object System.Windows.Forms.TreeView
$TreeView.Dock = [System.Windows.Forms.DockStyle]::Fill
$TreeView.TreeViewNodeSorter = New-Object -TypeName TreeNodeAlphanumComparator
$TreeView.ShowNodeToolTips = $true
$Form.Controls.Add($TreeView)

# top "search" strip
$MenuStrip = New-Object System.Windows.Forms.MenuStrip
$MenuStrip.ShowItemToolTips = $true
$MenuStrip.Dock = [System.Windows.Forms.DockStyle]::Top

$ExpandButton = New-Object System.Windows.Forms.ToolStripButton
$ExpandButton.Text = "+"
$ExpandButton.ToolTipText = "Expand All"
$ExpandButton.Add_Click({
    $TreeView.ExpandAll()
})

$CollapseButton = New-Object System.Windows.Forms.ToolStripButton
$CollapseButton.Text = "-"
$CollapseButton.ToolTipText = "Collapse All"
$CollapseButton.Add_Click({
    $TreeView.CollapseAll()
})
$ButtonSeparator = New-Object System.Windows.Forms.ToolStripSeparator

# Search
$SearchTextStrip = New-Object System.Windows.Forms.ToolStripStatusLabel
$SearchTextStrip.Text = "Search:"

$SearchBox = New-Object System.Windows.Forms.ToolStripTextBox
$SearchBox.Size = New-Object System.Drawing.Size(250, $SearchBox.Size.Height)
$SearchBox.Add_TextChanged({
    Search-Nodes
})

$SearchTextStrip2 = New-Object System.Windows.Forms.ToolStripStatusLabel
$SearchTextStrip2.Text = "Mode:"

$SearchModeDropDownButton = New-Object System.Windows.Forms.ToolStripDropDownButton
$SearchModeDropDown = New-Object System.Windows.Forms.ToolStripDropDown
[void] $SearchModeDropDown.Items.Add("Plaintext")
[void] $SearchModeDropDown.Items.Add("Extended")
[void] $SearchModeDropDown.Items.Add("RegEx")
$SearchModeDropDownButton.Text = $SearchModeDropDown.Items[0]
$SearchModeDropDownButton.DropDown = $SearchModeDropDown

$SearchModeDropDown.Add_ItemClicked({
    $SearchModeDropDownButton.Text = $_.ClickedItem.Text
    Search-Nodes
})

$SearchTextStrip3 = New-Object System.Windows.Forms.ToolStripStatusLabel
$SearchTextStrip3.Text = "Filter:"

$SearchLocationDropDownButton = New-Object System.Windows.Forms.ToolStripDropDownButton
$SearchLocationDropDown = New-Object System.Windows.Forms.ToolStripDropDown
[void] $SearchLocationDropDown.Items.Add("Everywhere")
[void] $SearchLocationDropDown.Items.Add("Call Chain")
$blacklistedSearchEntries = @("Sub-Processes")
foreach($property in $csvEntries[0].PSObject.Properties | Sort-Object) {
    if($property.Name -notin $blacklistedSearchEntries) {
        [void] $SearchLocationDropDown.Items.Add($property.Name)
    }
}
$SearchLocationDropDownButton.Text = $SearchLocationDropDown.Items[0]
$SearchLocationDropDownButton.DropDown = $SearchLocationDropDown

$SearchLocationDropDown.Add_ItemClicked({
    $SearchLocationDropDownButton.Text = $_.ClickedItem.Text
    Search-Nodes
})

# Dispay Mode Selection
$DisplayModeSeparator = New-Object System.Windows.Forms.ToolStripSeparator
$DisplayModeTextStrip = New-Object System.Windows.Forms.ToolStripStatusLabel
$DisplayModeTextStrip.Text = "Display Mode:"

$DisplayModeDropDown = New-Object System.Windows.Forms.ToolStripDropDown
[void] $DisplayModeDropDown.Items.Add("PID: Name")
[void] $DisplayModeDropDown.Items.Add("Name")

$DisplayModeDropDownButton = New-Object System.Windows.Forms.ToolStripDropDownButton
if($VisualPIDs) {
    $DisplayModeDropDownButton.Text = $DisplayModeDropDown.Items[0]
} else {
    $DisplayModeDropDownButton.Text = $DisplayModeDropDown.Items[1]
}
$DisplayModeDropDownButton.DropDown = $DisplayModeDropDown

$DisplayModeDropDown.Add_ItemClicked({
    $newValue = $_.ClickedItem.Text
    $currentValue = $DisplayModeDropDownButton.Text
    if($newValue -ne $currentValue) {
        $DisplayModeDropDownButton.Text = $newValue
        if($newValue -eq "PID: Name") {
            $VisualPIDs = $true
        } else {
            $VisualPIDs = $false
        }

        Fill-GUIData
    }
})

$MenuStrip.Items.AddRange($ExpandButton)
$MenuStrip.Items.AddRange($CollapseButton)
$MenuStrip.Items.AddRange($ButtonSeparator)

$MenuStrip.Items.AddRange($SearchTextStrip)
$MenuStrip.Items.AddRange($SearchBox)
$MenuStrip.Items.AddRange($SearchTextStrip2)
$MenuStrip.Items.AddRange($SearchModeDropDownButton)
$MenuStrip.Items.AddRange($SearchTextStrip3)
$MenuStrip.Items.AddRange($SearchLocationDropDownButton)

$MenuStrip.Items.AddRange($DisplayModeSeparator)
$MenuStrip.Items.AddRange($DisplayModeTextStrip)
$MenuStrip.Items.AddRange($DisplayModeDropDownButton)
$Form.Controls.Add($MenuStrip)

# bottom "statistics" strip
$StatusStrip = New-Object System.Windows.Forms.StatusStrip
$StatusStrip.Dock = [System.Windows.Forms.DockStyle]::Bottom
$StatusStrip.LayoutStyle = [System.Windows.Forms.ToolStripLayoutStyle]::HorizontalStackWithOverflow

# text block that lists the count of found elements in the bottom strip
$ElementCountLabel = New-Object System.Windows.Forms.ToolStripStatusLabel

$OSStartLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$OSStartLabel.Alignment = [System.Windows.Forms.ToolStripItemAlignment]::Right
$OSStartLabel.BorderStyle = [System.Windows.Forms.Border3DStyle]::Raised

$StatusStrip.Items.AddRange($ElementCountLabel)
$StatusStrip.Items.AddRange($OSStartLabel)
$Form.Controls.Add($StatusStrip)

####################################
#endregion GUI                     #
####################################


####################################
#region    DISPLAY                 #
####################################

$script:dataInitialised = $false

function Search-Nodes {
    $expandSet = [System.Collections.Generic.HashSet[System.Windows.Forms.TreeNode]]@()

    # iterate through all nodes in the treeview
    # and expand / collapse them according to the search
    $searchText = $SearchBox.Text
    $clear = $searchtext -eq ""
    $searchLocation = $SearchLocationDropDownButton.Text

    # Map search mode to an int (faster than string compare every time)
    # ideally use an enum here, but that's a newer PS feature
    [int] $searchMode = 0
    switch ($SearchModeDropDownButton.Text) {
        'PlainText' { $searchMode = 0}
        'Extended' { $searchMode = 1 }
        Default { # regex
            $searchMode = 2
            try {
                [regex] $searchText
            } catch {
                # current serach text is not valid regex
                return
            }
        }
    }

    $TreeView.BeginUpdate() # do not redraw the tree view everytime a property changes
   
    $queue = New-Object System.Collections.Queue
    foreach($node in $TreeView.Nodes) {
        $queue.Enqueue($node)
    }

    while($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        foreach($childNode in $node.Nodes) {
            $queue.Enqueue($childNode)
        }

        $node.Collapse()
        $node.BackColor = [System.Drawing.Color]::Transparent

        if(!$clear) {
            $element = $node.Tag
            $match = $false
            if($null -eq $element) {
                # node without element. Never matches
            } if($searchLocation -eq "Everywhere") {
                foreach($property in $element.PSObject.Properties) {
                    if($property.Name -eq "Call Chain") {
                        continue
                    }
                    if(Is-Match -Text $property.Value -SearchText $searchText -SearchMode $searchMode) {
                        $match = $true
                        break
                    }
                }
            } else {
                $match = Is-Match -Text $element.$searchLocation -SearchText $searchText -SearchMode $searchMode
            }

            if($match) {
                $node.BackColor = [System.Drawing.Color]::Yellow

                # note this node and all of it's parents to expand later
                $currentNode = $node
                do {
                    $expandSet.Add($currentNode)
                    $currentNode = $currentNode.Parent
                } while ($null -ne $currentNode)
            }
        }
    }

    foreach($expandEntry in $expandSet) {
        $expandEntry.expand()
    }
    $TreeView.EndUpdate()
}

function New-Node($ID, $Text, $Tooltip, $Parent, $Tag, [switch] $AddToMap) {
    $newNode = New-Object System.Windows.Forms.TreeNode
    $newNode.Name = $ID
    $newNode.Text = if($Text) { $Text } else { "<unknown>" }
    $newNode.ToolTipText = $Tooltip
    if($AddToMap) {
        $nodesMap[$ID] = $newNode
    }
    if($Tag) {
        $newNode.Tag = $Tag
    }
    if($Parent) {
        [void] $nodesMap[$Parent].Nodes.Add($newNode)
    } else {
        [void] $TreeView.Nodes.Add($newNode)
    }
}

function Set-Nodes($Root, $Depth, $Collapsed) {
    $TreeView.BeginUpdate() # do not redraw the tree view everytime a property changes
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([Tuple]::Create($Root, 0))

    while($queue.Count -gt 0) {
        $entry = $queue.Dequeue()
        $node = $entry.Item1
        $currentDepth = $entry.Item2

        if($currentDepth -lt $Depth) {
            foreach($childNode in $node.Nodes) {
                $queue.Enqueue([Tuple]::Create($childNode, $currentDepth + 1))
            }
        }

        if($collapsed) {
            $node.Collapse()
        } else {
            $node.Expand()
        }
   }
   $TreeView.EndUpdate()
}

<#
    In the tree view, we want nodes that are double clicked on, to show a properties view popup.
    Since by default, tree nodes have an event mapped to double click already (namely expanding / collapsing the node),
    we have to check if it's a double click in BeforeExpand() and BeforeCollapse() and cancel this default behavior
    so it does not interfere with the opening of our new properties window
    The user is still able to nagigate the tree via keyboard, or as usual, by using the +/- buttons on each node
#>
$script:CancelNodeExpanding = $false

function Fill-GUIData {
    $TreeView.BeginUpdate()
    $TreeView.Nodes.Clear()
    $TreeView.Add_KeyDown({
        # Ctrl+C override
        # If there is a better event handler please enlighten me
        # it makes the annoying "warning" sound, for whatever reason
        if($_.Control -and $_.KeyCode -eq "C") {
            $node = $TreeView.SelectedNode
            if($node -and $node.TooltipText) {
                [System.Windows.Forms.Clipboard]::SetDataObject($node.TooltipText)
            }
        }
    })
    $TreeView.Add_MouseDown({
        $script:CancelNodeExpanding = $_.Clicks -gt 1
    })
    $TreeView.Add_BeforeExpand({
        $_.Cancel = $script:CancelNodeExpanding
    })
    $TreeView.Add_BeforeCollapse({
        $_.Cancel = $script:CancelNodeExpanding
    })
    
    $TreeView.Add_NodeMouseDoubleClick({
        if($_.Node.Tag) {
            if(-not $_.Node.IsExpanded) {
                $_.Node.Expand()
            } else {
                $_.Node.Collapse();
            }

            Show-EntryWindow($_.Node.Tag)
            return $false
        }
    })
    $nodesMap = @{}
    
    $TotalProcesses = ($csvEntries).Count
    $RunningProcesses = ($csvEntries | Where-Object { $_."Exit Time" -eq "" }).Count
    $ExitedProcesses = ($csvEntries | Where-Object { $_."Exit Time" -ne "" }).Count
    $ElementCountLabel.Text = "Total Processes: $TotalProcesses | Running Processes: $RunningProcesses | Exited Processes: $ExitedProcesses"

    # a list of dedicated (root) nodes for special case handling
    $orphanID = $((New-Guid).Guid)
    New-Node -ID $orphanID -Text "Orphan Processes" -Tooltip "Processes where parent processes could not be found anymore" -AddToMap

    $notableID = $((New-Guid).Guid)
    New-Node -ID $notableID -Text "Alert Messages" -Tooltip "Common low hanging fruits" -AddToMap

    # LP_Windows Processes Suspicious Parent Directory Detected
    # Trigger Condition: Suspicious parent processes of Windows processes are detected.
    # ATT&CK Category: Defense Evasion
    # ATT&CK Tag: Masquerading
    $unusualRelationShipsID = $((New-Guid).Guid)
    New-Node -ID $unusualRelationShipsID -Text "Suspicious Parent-Child Relationships [T1036]" -Tooltip "Processes called from an unusual parent process" -Parent $notableID -AddToMap

    $scriptInterpretersID = $((New-Guid).Guid)
    New-Node -ID $scriptInterpretersID -Text "Command and Scripting Interpreters [T1059]" -Tooltip "CMD, Python, VB, Powershell, you name it" -Parent $notableID -AddToMap

    $suspiciousFoldersID = $((New-Guid).Guid)
    New-Node -ID $suspiciousFoldersID -Text "Suspicious Process File Path [T1543]" -Tooltip "Process Execution from an Unusual Directory" -Parent $notableID -AddToMap

    $lateralMovementProgramsID = $((New-Guid).Guid)
    New-Node -ID $lateralMovementProgramsID -Text "Lateral Movement Tools [TA0008]" -Tooltip "Process Execution from an Unusual Directory" -Parent $notableID -AddToMap

    $suspiciousProgramsID = $((New-Guid).Guid)
    New-Node -ID $suspiciousProgramsID -Text "Suspicious Program Execution [T1218, T1127.001, T1087.002]" -Tooltip "All kinds of suspicious Programs, usually used for Discovery, Privilege Escalation to Proxy Execution" -Parent $notableID -AddToMap

    $doubleFileExtensionsID = $((New-Guid).Guid)
    New-Node -ID $doubleFileExtensionsID -Text "Double File Extensions [T1036.007]" -Tooltip "Processes spawned from execuables using a double file extension, most often in a way to deceive users to execute malicious payloads, like 'invoice.doc.exe'" -Parent $notableID -AddToMap

    $suspiciousParametersID = $((New-Guid).Guid)
    New-Node -ID $suspiciousParametersID -Text "Suspicious Command Line Parameters" -Tooltip "Command Line Parameters that are oftentimes used my malware" -Parent $notableID -AddToMap

    $expectedRelationshipDiscrepancyID = $((New-Guid).Guid)
    New-Node -ID $expectedRelationshipDiscrepancyID -Text "Processes with different Parent than usual [T1036.005]" -Tooltip "The process loading chain of system processes is mostly fixed, like lsass.exe always getting started via wininit.exe. Are there discrepancies, chances are they got started for means of process injection, or by giving a malicious payload the same name as a known good process, but in a different path." -Parent $notableID -AddToMap
    
    $expectedProcessPathDiscrepancyID = $((New-Guid).Guid)
    New-Node -ID $expectedProcessPathDiscrepancyID -Text "Known Process Names in different Path [T1036.005]" -Tooltip "System processes have a dedicated path where their executables are stored (such as in %windir%). If a process with a well known name runs in a different folder, chances are it is malicious and the name was chosen to fly under the radar" -Parent $notableID -AddToMap
    
    $expectedProcessInstanceDiscrepancyID = $((New-Guid).Guid)
    New-Node -ID $expectedProcessInstanceDiscrepancyID -Text "Process instance count mismatch [T1036.005]" -Tooltip "Lots of system processes have a fixed number of instances runnung simultaneously - most often 1. If there are more, chances are they got started for means of process injection, or by giving a malicious payload the same name as a known good process, but in a different path." -Parent $notableID -AddToMap
    
    $ProcessNameMasqueradingID = $((New-Guid).Guid)
    New-Node -ID $ProcessNameMasqueradingID -Text "Process Name Masquerading [T1036.005]" -Tooltip "Attackers name their payloads similar to known system processes to avoid detection. Something like 'lsaas.exe' closely resembles the legitimate 'lsass.exe' on first glance." -Parent $notableID -AddToMap

    $runningInUNCNetworkPathID = $((New-Guid).Guid)
    New-Node -ID $runningInUNCNetworkPathID -Text "Processes running from UNC Network Paths" -Tooltip "Processes running in UNC paths can hint to remote execution through file shares without having to copy malicious files to the local system" -Parent $notableID -AddToMap

    # create nodes, but not attach them yet. It will make parent search possible.
    foreach ($csvEntry in $csvEntries) {
        # Add a "Suspicious" attribute
        Add-Member -InputObject $csvEntry -MemberType NoteProperty -Name "Suspicious" -Value ""

        $newNode = New-Object System.Windows.Forms.TreeNode
        if($VisualPIDs) {
            $newNode.Text = $(if($csvEntry.PID) { $csvEntry.PID } else { "???" }) + ": " + $(if($csvEntry."Process Name") { $csvEntry."Process Name" } else { "<unknown>" })
        } else {
            $newNode.Text = if($csvEntry."Process Name") { $csvEntry."Process Name" } else { "<unknown>" }
        }

        # custom handling for svchost.exe
        # add command line parameters to displayed node
        if($csvEntry."Process Name" -eq "svchost.exe") {
            $newText = $newNode.Text
            $svcHostS = $null
            $svcHostK = $null
            if($csvEntry.CommandLine -match "-s (\w+)") {
                $svcHostS = $Matches[0] -replace "-s ", ""
            }
            if($csvEntry.CommandLine -match "-k (\w+)") {
                $svcHostK = $Matches[0] -replace "-k ", ""
            }
            if($svcHostK) {
                $newNode.Text = $newText + " " + (Get-SVCHostData -K $svcHostK -S $svcHostS)
            }
        }

        $newNode.Name = $csvEntry.PID
        $newNode.Tag = $csvEntry
        $newNode.ToolTipText = ($csvEntry | Out-String).Trim() -replace " *:", ":"
        $nodesMap[$csvEntry.PID] = $newNode
    }

    # iterate all nodes and attach each node to its parent
    foreach ($entry in $nodesMap.GetEnumerator()) {
        # skip nodes without tag (root tags)
        if($null -eq $entry.Value.Tag) {
            continue
        }
    
        $currPID = $entry.Key
        $currNode = $entry.Value
        $currProcess = $entry.Value.Tag
    
        # PID 4 is the known PID of the system process
        # this is where the system started up. Note startup time in the entry
        # this entry will be used as root, therefore it does not need
        # to get attached to an other element
        if ($currProcess.PID -eq 4) {
            $OSStartLabel.Text = "Windows Start: " + $currProcess."Create Time"
            [void] $TreeView.Nodes.Add($nodesMap[$currPID])
            continue
        }

        # entries who PPID does not exist get attached to the ORPHANS node instead
        $parentNode = $nodesMap[$currProcess.PPID]
        if ($null -eq $parentNode) {
            $parentNode = $orphanNode
            $currProcess.Suspicious = "Orphaned"
        }
    
        # attach this node to the element with matching PID => PPID
        $cyclicalPIDRelationship = $false
        $cyclicalParent = $false
        $PIDTreeList = New-Object System.Collections.ArrayList

        $checkProcess = $currProcess
        $checkNode = $currNode
        $orphanNode = $nodesMap[$orphanID]
        Write-Verbose "Starting with $($checkProcess.PID)"
        while($checkProcess) {
            if($checkNode.Parent -eq $orphanNode) {
                Write-Verbose ".......PID $($checkProcess.PID) is already known having a cyclical PID relationship. Aborting."
                $cyclicalParent = $true
                break
            }
            [void] $PIDTreeList.Add($checkProcess.PID)
            $checkNode = $nodesMap[$checkProcess.PPID]
            $checkProcess = $checkNode.Tag
            Write-Verbose "...checking $($checkProcess.PID) (Tree: $($PIDTreeList))"
            if($PIDTreeList.Contains($checkProcess.PID)) {
                Write-Verbose "......cyclical pid<=>ppid relationship found: PID $($checkProcess.PID)"
                $cyclicalPIDRelationship = $true
                break
            }
        }

        if($cyclicalPIDRelationship) {
            if(-not $orphanNode.Nodes.Contains($checkNode)) {
                Note-Suspicious -Node $checkNode -Description "Cyclical PID Relationship (Process with PID $($checkProcess.PPID) is a child process of this)"
                [void] $orphanNode.Nodes.Add($checkNode)
            }
        }

        if($cyclicalParent -and $checkProcess -eq $currProcess) {
            Write-Verbose "NOT ADDING $($currProcess.PID) to node with PID $($nodesMap[$currProcess.PPID].Tag.PID) - currently already: $($nodesMap[$currProcess.PPID].Nodes.Tag.PID)"
        } else {
            Write-Verbose "Adding $($currProcess.PID) to node with PID $($nodesMap[$currProcess.PPID].Tag.PID) - currently already: $($nodesMap[$currProcess.PPID].Nodes.Tag.PID)"
            [void] $parentNode.Nodes.Add($currNode)
        }
    }

    # one last iteration: add a full path property to all nodes
    foreach ($node in @($nodesMap.Values)) {
        $process = $node.Tag
        if($null -ne $process) {        
            # Add a "Call Chain" attribute
            $processTree = $node.Text
            $currentNode = $node
            while($null -ne $currentNode.Parent -and $null -ne $currentNode.Parent.Tag) {
                $parentNode = $currentNode.Parent
                $processTree = $parentNode.Tag.'Process Name' + " → " + $processTree
                $currentNode = $parentNode
            }

            if($script:dataInitialised) {
                $process."Call Chain" = $processTree
            } else {
                Add-Member -InputObject $process -MemberType NoteProperty -Name "Call Chain" -Value $processTree
            }

            $node.ToolTipText = ($process | Out-String).Trim() -replace " *:", ":"
        }

        if(-not $NoSuspiciousChecks) {
            # enumerate each process and search if they match any notable criteria
            # script interpreters
            if($null -ne $process.'Process Name') {
                # script interpreters
                if ($process.'Process Name' -in $scriptInterpreters) {
                    Set-Suspicious -Node $node -ParentID $scriptInterpretersID -Description "Script Interpreter" -ShortId "in"
                }

                # lateral movement programs
                if($process.'Process Name' -in $LateralMovementPrograms) {
                    Set-Suspicious -Node $node -ParentID $lateralMovementProgramsID -Description "Lateral Movement Program" -ShortId "lm"
                }

                # suspicious programs
                if($process.'Process Name' -in $SuspiciousPrograms) {
                    Set-Suspicious -Node $node -ParentID $suspiciousProgramsID -Description "Suspicious Program" -ShortId "sp"
                }

                # double file extensions
                if($process.'Process Name') {
                    $dotCount = ($process.'Process Name'.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
                    if($dotCount -gt 1) {
                        Set-Suspicious -Node $node -ParentID $doubleFileExtensionsID -Description "Double File Extension" -ShortId "dfe"
                    }
                }

                # suspicious parameters
                if($process.CommandLine) {
                    foreach($suspiciousParameter in $SuspiciousParameters) {
                        if($process.'Process Name' -like $suspiciousParameter.Item1 -and $process.CommandLine -like $suspiciousParameter.Item2) {
                            Set-Suspicious -Node $node -ParentID $suspiciousParametersID -Description "Suspicious Command Line Parameters" -ShortId "sparam"
                        }
                    }
                }

                # known good processes but with unusual parent
                if($ExpectedRelationships.ContainsKey($process.'Process Name')) {
                    $acceptableParents = $ExpectedRelationships[$process.'Process Name']
                    $parentProcessNode = $nodesMap[$process.PPID]
                    if($null -ne $parentProcessNode -and $null -ne $parentProcessNode.Tag) {
                        if($parentProcessNode.Tag.'Process Name' -notin $acceptableParents) {
                            Set-Suspicious -Node $node -ParentID $expectedRelationshipDiscrepancyID -Description $("Parent process mismatch. Should match one of: " + $acceptableParents -join ", ") -ShortId "accp"
                        }
                    }
                }

                # check the number of running instances with the same process name.
                # does the found count match the expected count?
                if($ExpectedProcessInstanceCounts.ContainsKey($process.'Process Name')) {
                    $expectedInstances = $ExpectedProcessInstanceCounts[$process.'Process Name']
                    [int] $runningInstances = 0 # the upcoming loop also counts this instance, so we start at 0 instead of 1
                    foreach($mapNode in $nodesMap.Values) {
                        if($null -ne $mapNode.Tag -and $process.'Process Name' -eq $mapNode.Tag.'Process Name') {
                            $runningInstances++
                        }
                    }
                    if($expectedInstances -ne $runningInstances) {
                        Set-Suspicious -Node $node -ParentID $expectedProcessInstanceDiscrepancyID -Description $("Found " + $runningInstances + " running instances instead of the expected " + $expectedInstances) -ShortId "eicm"
                    }
                }

                # check if this process name is typed very similar than known good ones
                foreach($similarName in $ProcessesToSearchSimilarNames) {
                    [int] $distance = [LevenshteinDistance]::Measure($process.'Process Name', $similarName)
                    if($distance -eq 1) {
                        Set-Suspicious -Node $node -ParentID $ProcessNameMasqueradingID -Description $("Name " + $process.'Process Name' + " is very similar to known " + $similarName) -ShortId "pnm"
                    }
                }
            }

            if($null -ne $process.'File Path') {
                # unusual file locations
                foreach($suspiciousFolder in $suspiciousFolders) {
                    if($process.'File Path' -like $suspiciousFolder) {
                        Set-Suspicious -Node $node -ParentID $suspiciousFoldersID -Description "Running in Suspicious Folder" -ShortId "sf"
                        break
                    }
                }
        
                # unusual parent <=> child relationship
                if($node.Tag.PID -and $nodesMap.ContainsKey($node.Tag.PID)) {
                    $parentNode = $nodesMap[$node.Tag.PID]
                    if($null -ne $parentNode -and $null -ne $parentNode.Tag -and $null -ne $parentNode.Tag.'Process Name') {
                        $parentProcess = $parent.Tag
                        foreach($unusualRelationShip in $unusualRelationShips) {
                            if($parentProcess.'Process Name' -like $unusualRelationShip.Item1 -and $process.'File Path' -like $unusualRelationShip.Item2) {
                                Set-Suspicious -Node $node -ParentID $unusualRelationShipsID -Description "Unusual Parent<=>Child Relationship" -ShortId "ur"
                                break
                            }
                        }
                    }
                }

                # known good programs, but in unusual path
                if($null -ne $process.'Process Name' -and $ExpectedProcessPaths.ContainsKey($process.'Process Name')) {
                    $knownPath = $ExpectedProcessPaths[$process.'Process Name']
                    if($process.'Device Path' -notmatch $knownPath) {
                        Set-Suspicious -Node $node -ParentID $expectedProcessPathDiscrepancyID -Description $("Process Path mismatch. Should match: '" + $knownPath + "'") -ShortId "kppm"
                    }
                }

                # running in unc path
                if($process.'File Path'.StartsWith("\\")) {
                    Set-Suspicious -Node $node -ParentID $runningInUNCNetworkPathID -Description $("Running in UNC network path") -ShortId "unc"
                }

            }
        }

    }

    $TreeView.Sort()

    $systemNode = $nodesMap["4"]
    if($systemNode) {
        Set-Nodes -Root $systemNode -Depth 3 -Collapsed $false
    }

    $TreeView.EndUpdate()

    $script:dataInitialised = $true
}


####################################
#endregion DISPLAY                 #
####################################

Fill-GUIData

$Form.Add_Shown( { $Form.Activate() })
[system.windows.forms.application]::run($Form)