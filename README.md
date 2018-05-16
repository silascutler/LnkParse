# LnkParse
Windows Shortcut file (LNK) parser


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
