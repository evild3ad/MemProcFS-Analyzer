rule LNK
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detects Windows Shortcut File (LNK)"
		date = "2021-04-05"
		filetype = "File System Scan"

	condition:
	 	uint16(0) == 0x004c and uint32(4) == 0x00021401 // Header Magic (LNK)
        and filesize < 2MB
}