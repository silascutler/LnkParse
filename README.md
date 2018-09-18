# LnkParse
Windows Shortcut file (LNK) parser

https://msdn.microsoft.com/en-us/library/dd871305.aspx

Install:
`pip install lnkfile`


Example:

```
$ python lnk_parser.py 70f26580777a87804dd7419c5121f40e 
Windows Shortcut Information:
	Link Flags: HasLinkInfo | IsUnicode | HasTargetIDList | DisableKnownFolderTracking | HasRelativePath - (2097291)
	File Flags: FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED - (8224)

	Creation Timestamp: 2011-09-26 22:23:23
	Modified Timestamp: 2011-09-26 22:23:23
	Accessed Timestamp: 2011-09-26 22:23:23

	File Size: 1555369 (r: 505)
	Icon Index: 0 
	Window Style: SW_NORMAL 
	HotKey: UNSET -  {0x0000} 

	relativePath: ..\..\..\..\..\Downloads\RDP.zip

	EXTRA BLOCKS:
		METADATA_PRPERTIES_BLOCK
		DISTRIBUTED_LINK_TRACKER_BLOCK
			[droid_volume_identifier] 54f13791b375c04eba3e01036f721401
			[birth_droid_volume_identifier] 54f13791b375c04eba3e01036f721401
			[machine_identifier] aris-pc
			[droid_file_identifier] ac9f69364458e8119b2682a5f086db87
			[version] 0
			[birth_droid_file_identifier] ac9f69364458e8119b2682a5f086db87
			[size] 88
```


and
```
>>> import lnkfile
>>> indata = open('tests/microsoft_example.lnk', 'rb')
>>> x = lnkfile.lnk_file(indata)
>>> x.print_lnk_file()
Windows Shortcut Information:
	Link Flags: HasLinkInfo | EnableTargetMetadata | HasWorkingDir | IsUnicode | HasTargetIDList | HasRelativePath - (524443)
	File Flags: FILE_ATTRIBUTE_ARCHIVE - (32)

	Creation Timestamp: 2010-10-08 17:14:43
	Modified Timestamp: 2010-10-08 17:14:43
	Accessed Timestamp: 2010-10-08 17:14:43

	File Size: 0 (r: 459)
	Icon Index: 0 
	Window Style: SW_NORMAL 
	HotKey: UNSET -  {0x0000} 

	relativePath: .\a.txt
	workingDirectory: C:\test

	EXTRA BLOCKS:
		DISTRIBUTED_LINK_TRACKER_BLOCK
			[droid_volume_identifier] 4078c79447fac746b3565c2dc6b6d115
			[birth_droid_volume_identifier] 4078c79447fac746b3565c2dc6b6d115
			[machine_identifier] chris-xps
			[droid_file_identifier] ec46cd7b227fdd11949900137216874a
			[version] 0
			[birth_droid_file_identifier] ec46cd7b227fdd11949900137216874a
			[size] 88

>>> x.print_json()
{"header": {"windowstyle": "SW_NORMAL", "rfile_size": "00000000", "linkFlags": 524443, "creation_time": 128657248371010000, "header_size": 76, "rhotkey": 0, "icon_index": 0, "fileFlags": 32, "modified_time": 128657248371010000, "file_size": 0, "hotkey": "UNSET -  {0x0000}", "accessed_time": 128657248371010000, "guid": "0114020000000000c000000000000046", "reserved1": 0, "reserved0": 0, "reserved2": 0}, "data": {"relativePath": ".\\a.txt", "workingDirectory": "C:\\test"}, "extra": {"DISTRIBUTED_LINK_TRACKER_BLOCK": {"droid_volume_identifier": "4078c79447fac746b3565c2dc6b6d115", "birth_droid_volume_identifier": "4078c79447fac746b3565c2dc6b6d115", "machine_identifier": "chris-xps", "droid_file_identifier": "ec46cd7b227fdd11949900137216874a", "version": 0, "birth_droid_file_identifier": "ec46cd7b227fdd11949900137216874a", "size": 88}}}

```

