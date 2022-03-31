#!/usr/bin/env python3
# 2016 - Silas Cutler (silas.cutler@blacklistthisdomain.com)

__description__ = 'Windows Shortcut file (LNK) parser'
__author__ = 'Silas Cutler'
__version__ = '0.2.1'

import sys
import json
import struct
import datetime
import argparse


class lnk_file(object):
	def __init__(self, fhandle=None, indata=None, debug=False):
		self.define_static()

		if fhandle:
			self.indata = fhandle.read()
		elif indata:
			self.indata = indata

		self.debug = debug
		self.lnk_header = {}

		self.linkFlag = {
			'HasTargetIDList': False,
			'HasLinkInfo': False,
			'HasName': False,
			'HasRelativePath': False,
			'HasWorkingDir': False,
			'HasArguments': False,
			'HasIconLocation': False,
			'IsUnicode': False,
			'ForceNoLinkInfo': False,
			'HasExpString': False,
			'RunInSeparateProcess': False,
			'Reserved0': False,
			'HasDarwinID': False,
			'RunAsUser': False,
			'HasExpIcon': False,
			'NoPidlAlias': False,
			'Reserved1': False,
			'RunWithShimLayer': False,
			'ForceNoLinkTrack': False,
			'EnableTargetMetadata': False,
			'DisableLinkPathTracking': False,
			'DisableKnownFolderTracking': False,
			'DisableKnownFolderAlias': False,
			'AllowLinkToLink': False,
			'UnaliasOnSave': False,
			'PreferEnvironmentPath': False,
			'KeepLocalIDListForUNCTarget': False,
		}
		self.fileFlag = {
			'FILE_ATTRIBUTE_READONLY': False,
			'FILE_ATTRIBUTE_HIDDEN': False,
			'FILE_ATTRIBUTE_SYSTEM': False,
			'Reserved, not used by the LNK format': False,
			'FILE_ATTRIBUTE_DIRECTORY': False,
			'FILE_ATTRIBUTE_ARCHIVE': False,
			'FILE_ATTRIBUTE_DEVICE': False,
			'FILE_ATTRIBUTE_NORMAL': False,
			'FILE_ATTRIBUTE_TEMPORARY': False,
			'FILE_ATTRIBUTE_SPARSE_FILE': False,
			'FILE_ATTRIBUTE_REPARSE_POINT': False,
			'FILE_ATTRIBUTE_COMPRESSED': False,
			'FILE_ATTRIBUTE_OFFLINE': False,
			'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED': False,
			'FILE_ATTRIBUTE_ENCRYPTED': False,
			'Unknown (seen on Windows 95 FAT)': False,
			'FILE_ATTRIBUTE_VIRTUAL': False,
		}

		self.targets = {
			'size': 0,
			'items': [],
		}

		self.loc_information = {}
		self.data = {}
		self.extraBlocks = {}

		self.process()
		self.define_common()

	def define_common(self):
		try:
			out = ''
			if self.linkFlag['HasRelativePath']:
				out += self.data['relativePath']
			if self.linkFlag['HasArguments']:
				out += ' ' + self.data['commandLineArguments']

			self.lnk_command = out
		except Exception as e:
			if self.debug:
				print('Exception define_common: %s' % e)

	def get_command(self):
		try:
			out = ''
			if self.linkFlag['HasRelativePath']:
				out += self.data['relativePath']
			if self.linkFlag['HasArguments']:
				out += ' ' + self.data['commandLineArguments']

			return out
		except Exception as e:
			if self.debug:
				print('Exception get_command: %s' % (e))
			return ''

	def define_static(self):
		# Define static constents used within the LNK format

		# Each MAGIC string refernces a function for processing
		self.EXTRA_SIGS = {
			'a0000001': self.parse_environment_block,
			'a0000002': self.parse_console_block,
			'a0000003': self.parse_distributedTracker_block,
			'a0000004': self.parse_codepage_block,
			'a0000005': self.parse_specialFolder_block,
			'a0000006': self.parse_darwin_block,
			'a0000007': self.parse_icon_block,
			'a0000008': self.parse_shimLayer_block,
			'a0000009': self.parse_metadata_block,
			'a000000b': self.parse_knownFolder_block,
			'a000000c': self.parse_shellItem_block,
		}

		self.DRIVE_TYPES = [
			'DRIVE_UNKNOWN',
			'DRIVE_NO_ROOT_DIR',
			'DRIVE_REMOVABLE',
			'DRIVE_FIXED',
			'DRIVE_REMOTE',
			'DRIVE_CDROM',
			'DRIVE_RAMDISK',
		]
		self.HOTKEY_VALUES = {
			'\x00': 'UNSET',
			'\x01': 'HOTKEYF_SHIFT',
			'\x02': 'HOTKEYF_CONTROL',
			'\x03': 'HOTKEYF_ALT',
		}
		self.WINDOWSTYLES = [
			'SW_HIDE',
			'SW_NORMAL',
			'SW_SHOWMINIMIZED',
			'SW_MAXIMIZE ',
			'SW_SHOWNOACTIVATE',
			'SW_SHOW',
			'SW_MINIMIZE',
			'SW_SHOWMINNOACTIVE',
			'SW_SHOWNA',
			'SW_RESTORE',
			'SW_SHOWDEFAULT',
		]

	@staticmethod
	def clean_line(rstring):
		return ''.join(chr(i) for i in rstring if 128 > i > 20)

	def to_guid(self, data, variant = 2):
		if len(data) != 16:
			return data.hex()
		if variant == 2:
			data = data[0:4][::-1] + data[4:6][::-1] + data[6:8][::-1] + data[8:]
		guid = '{' + data[0:4].hex() + '-' + data[4:6].hex() +  '-' + data[6:8].hex() + \
			 '-' + data[8:10].hex() + '-' + data[10:].hex() + '}'
		return guid

	def parse_lnk_header(self):
		# Parse the LNK file header
		try:
			# Header always starts with { 4c 00 00 00 } and is the size of the header
			self.lnk_header['header_size'] = struct.unpack('<I', self.indata[:4])[0]

			lnk_header = self.indata[:self.lnk_header['header_size']]

			self.lnk_header['guid'] = lnk_header[4:20].hex()

			self.lnk_header['rlinkFlags'] = struct.unpack('<i', lnk_header[20:24])[0]
			self.lnk_header['rfileFlags'] = struct.unpack('<i', lnk_header[24:28])[0]

			self.lnk_header['creation_time'] = struct.unpack('<q', lnk_header[28:36])[0]
			self.lnk_header['accessed_time'] = struct.unpack('<q', lnk_header[36:44])[0]
			self.lnk_header['modified_time'] = struct.unpack('<q', lnk_header[44:52])[0]

			self.lnk_header['file_size'] = struct.unpack('<i', lnk_header[52:56])[0]
			self.lnk_header['rfile_size'] = lnk_header[52:56].hex()

			self.lnk_header['icon_index'] = struct.unpack('<I', lnk_header[56:60])[0]
			try:
				if struct.unpack('<i', lnk_header[60:64])[0] < len(self.WINDOWSTYLES):
					self.lnk_header['windowstyle'] = self.WINDOWSTYLES[
						struct.unpack('<i', lnk_header[60:64])[0]]
				else:
					self.lnk_header['windowstyle'] = struct.unpack('<i', lnk_header[60:64])[0]
			except Exception as e:
				if self.debug:
					print('Error Parsing WindowStyle in Header: %s' % e)
				self.lnk_header['windowstyle'] = struct.unpack('<i', lnk_header[60:64])[0]

			try:
				self.lnk_header['hotkey'] = '%s - %s {0x%s}' % (
					self.HOTKEY_VALUES[chr(struct.unpack('<B', lnk_header[65:66])[0])],
					self.clean_line(struct.unpack('<B', lnk_header[64:65])),
					lnk_header[64:66].hex()
				)

				self.lnk_header['rhotkey'] = struct.unpack('<H', lnk_header[64:66])[0]
			except Exception as e:
				if self.debug:
					print('Exception parsing HOTKEY part of header: %s' % e)
					print(lnk_header[65:66].hex())
				self.lnk_header['hotkey'] = struct.unpack('<H', lnk_header[64:66])[0]

			self.lnk_header['reserved0'] = struct.unpack('<H', lnk_header[66:68])[0]
			self.lnk_header['reserved1'] = struct.unpack('<i', lnk_header[68:72])[0]
			self.lnk_header['reserved2'] = struct.unpack('<i', lnk_header[72:76])[0]
		except Exception as e:
			if self.debug:
				print('Exception parsing LNK Header: %s' % e)
			return False

		if self.lnk_header['header_size'] == 76:
			return True

	def parse_link_flags(self):
		if self.lnk_header['rlinkFlags'] & 0x00000001:
			self.linkFlag['HasTargetIDList'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000002:
			self.linkFlag['HasLinkInfo'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000004:
			self.linkFlag['HasName'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000008:
			self.linkFlag['HasRelativePath'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000010:
			self.linkFlag['HasWorkingDir'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000020:
			self.linkFlag['HasArguments'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000040:
			self.linkFlag['HasIconLocation'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000080:
			self.linkFlag['IsUnicode'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000100:
			self.linkFlag['ForceNoLinkInfo'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000200:
			self.linkFlag['HasExpString'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000400:
			self.linkFlag['RunInSeparateProcess'] = True
		if self.lnk_header['rlinkFlags'] & 0x00000800:
			self.linkFlag['Reserved0'] = True
		if self.lnk_header['rlinkFlags'] & 0x00001000:
			self.linkFlag['HasDarwinID'] = True
		if self.lnk_header['rlinkFlags'] & 0x00002000:
			self.linkFlag['RunAsUser'] = True
		if self.lnk_header['rlinkFlags'] & 0x00004000:
			self.linkFlag['HasExpIcon'] = True
		if self.lnk_header['rlinkFlags'] & 0x00008000:
			self.linkFlag['NoPidlAlias'] = True
		if self.lnk_header['rlinkFlags'] & 0x00010000:
			self.linkFlag['Reserved1'] = True
		if self.lnk_header['rlinkFlags'] & 0x00020000:
			self.linkFlag['RunWithShimLayer'] = True
		if self.lnk_header['rlinkFlags'] & 0x00040000:
			self.linkFlag['ForceNoLinkTrack'] = True
		if self.lnk_header['rlinkFlags'] & 0x00080000:
			self.linkFlag['EnableTargetMetadata'] = True
		if self.lnk_header['rlinkFlags'] & 0x00100000:
			self.linkFlag['DisableLinkPathTracking'] = True
		if self.lnk_header['rlinkFlags'] & 0x00200000:
			self.linkFlag['DisableKnownFolderTracking'] = True
		if self.lnk_header['rlinkFlags'] & 0x00400000:
			self.linkFlag['DisableKnownFolderAlias'] = True
		if self.lnk_header['rlinkFlags'] & 0x00800000:
			self.linkFlag['AllowLinkToLink'] = True
		if self.lnk_header['rlinkFlags'] & 0x01000000:
			self.linkFlag['UnaliasOnSave'] = True
		if self.lnk_header['rlinkFlags'] & 0x02000000:
			self.linkFlag['PreferEnvironmentPath'] = True
		if self.lnk_header['rlinkFlags'] & 0x04000000:
			self.linkFlag['KeepLocalIDListForUNCTarget'] = True

		self.lnk_header['linkFlags'] = self.enabled_flags_to_list(self.linkFlag)

	def parse_file_flags(self):
		if self.lnk_header['rfileFlags'] & 0x00000001:
			self.fileFlag['FILE_ATTRIBUTE_READONLY'] = True
		if self.lnk_header['rfileFlags'] & 0x00000002:
			self.fileFlag['FILE_ATTRIBUTE_HIDDEN'] = True
		if self.lnk_header['rfileFlags'] & 0x00000004:
			self.fileFlag['FILE_ATTRIBUTE_SYSTEM'] = True
		if self.lnk_header['rfileFlags'] & 0x00000008:
			self.fileFlag['Reserved, not used by the LNK format'] = True
		if self.lnk_header['rfileFlags'] & 0x00000010:
			self.fileFlag['FILE_ATTRIBUTE_DIRECTORY'] = True
		if self.lnk_header['rfileFlags'] & 0x00000020:
			self.fileFlag['FILE_ATTRIBUTE_ARCHIVE'] = True
		if self.lnk_header['rfileFlags'] & 0x00000040:
			self.fileFlag['FILE_ATTRIBUTE_DEVICE'] = True
		if self.lnk_header['rfileFlags'] & 0x00000080:
			self.fileFlag['FILE_ATTRIBUTE_NORMAL'] = True
		if self.lnk_header['rfileFlags'] & 0x00000100:
			self.fileFlag['FILE_ATTRIBUTE_TEMPORARY'] = True
		if self.lnk_header['rfileFlags'] & 0x00000200:
			self.fileFlag['FILE_ATTRIBUTE_SPARSE_FILE'] = True
		if self.lnk_header['rfileFlags'] & 0x00000400:
			self.fileFlag['FILE_ATTRIBUTE_REPARSE_POINT'] = True
		if self.lnk_header['rfileFlags'] & 0x00000800:
			self.fileFlag['FILE_ATTRIBUTE_COMPRESSED'] = True
		if self.lnk_header['rfileFlags'] & 0x00001000:
			self.fileFlag['FILE_ATTRIBUTE_OFFLINE'] = True
		if self.lnk_header['rfileFlags'] & 0x00002000:
			self.fileFlag['FILE_ATTRIBUTE_NOT_CONTENT_INDEXED'] = True
		if self.lnk_header['rfileFlags'] & 0x00004000:
			self.fileFlag['FILE_ATTRIBUTE_ENCRYPTED'] = True
		if self.lnk_header['rfileFlags'] & 0x00008000:
			self.fileFlag['Unknown (seen on Windows 95 FAT)'] = True
		if self.lnk_header['rfileFlags'] & 0x00010000:
			self.fileFlag['FILE_ATTRIBUTE_VIRTUAL'] = True

		self.lnk_header['fileFlags'] = self.enabled_flags_to_list(self.fileFlag)

	def parse_link_information(self):
		index = 0
		while True:
			tmp_item = {}
			tmp_item['size'] = struct.unpack('<H', self.link_target_list[index: index + 2])[0]
			tmp_item['rsize'] = self.link_target_list[index: index + 2].hex()

			self.items.append(tmp_item)
			index += tmp_item['size']

			return ''

	# Still in development // repair
	def parse_targets(self, index):
		max_size = self.targets['size'] + index

		while (index < max_size):
			ItemID = {
				'size': struct.unpack('<H', self.indata[index: index + 2])[0],
				'type': struct.unpack('<B', self.indata[index + 2: index + 3])[0],
			}
			index += 3

			#           self.targets['items'].append( self.indata[index: index + ItemID['size']].replace('\x00','') )
			#           print('[%s] %s' % (ItemID['size'], hex(ItemID['type']) )#, self.indata[index: index + ItemID['size']].replace('\x00','') ))
			#           print(self.indata[ index: index + ItemID['size'] ].hex()[:50])
			index += ItemID['size']

	#           print(self.indata[index + 2: index + 2 + ItemID['size']].replace('\x00',''))

	def process(self):
		index = 0
		if not self.parse_lnk_header():
			print('Failed Header Check')

		self.parse_link_flags()
		self.parse_file_flags()
		index += self.lnk_header['header_size']

		# Parse ID List
		if self.linkFlag['HasTargetIDList']:
			try:
				self.targets['size'] = struct.unpack('<H', self.indata[index: index + 2])[0]
				index += 2
				if self.debug:
					self.parse_targets(index)
				index += self.targets['size']
			except Exception as e:
				if self.debug:
					print('Exception parsing TargetIDList: %s' % e)
				return False

		if self.linkFlag['HasLinkInfo'] and self.linkFlag['ForceNoLinkInfo'] == False:
			try:
				self.loc_information = {
					'LinkInfoSize': struct.unpack('<i', self.indata[index: index + 4])[0],
					'LinkInfoHeaderSize': struct.unpack('<i', self.indata[index + 4: index + 8])[0],
					'LinkInfoFlags': struct.unpack('<i', self.indata[index + 8: index + 12])[0],
					'VolumeIDOffset': struct.unpack('<i', self.indata[index + 12: index + 16])[0],
					'LocalBasePathOffset': struct.unpack('<i', self.indata[index + 16: index + 20])[0],
					'CommonNetworkRelativeLinkOffset': struct.unpack('<i', self.indata[index + 20: index + 24])[0],
					'CommonPathSuffixOffset': struct.unpack('<i', self.indata[index + 24: index + 28])[0],
				}

				if self.loc_information['LinkInfoFlags'] & 0x0001:
					if self.loc_information['LinkInfoHeaderSize'] >= 36:
						self.loc_information['o_LocalBasePathOffsetUnicode'] = \
								struct.unpack('<i', self.indata[index + 28: index + 32])[0]
						local_index = index + self.loc_information['o_LocalBasePathOffsetUnicode']
						self.loc_information['o_LocalBasePathUnicode'] = \
								struct.unpack('<i', self.indata[local_index: local_index + 4])[0]
					else:
						local_index = index + self.loc_information['LocalBasePathOffset']
						self.loc_information['LocalBasePath'] = self.read_string(local_index)

					local_index = index + self.loc_information['VolumeIDOffset']
					self.loc_information['location'] = 'VolumeIDAndLocalBasePath'
					self.loc_information['VolumeIDAndLocalBasePath'] = {
						'VolumeIDSize':
							struct.unpack('<i', self.indata[local_index + 0: local_index + 4])[0],
						'rDriveType':
							struct.unpack('<i', self.indata[local_index + 4: local_index + 8])[0],
						'DriveSerialNumber': hex(
							struct.unpack('<i', self.indata[local_index + 8: local_index + 12])[0]),
						'VolumeLabelOffset':
							struct.unpack('<i', self.indata[local_index + 12: local_index + 16])[0],
					}

					if self.loc_information['VolumeIDAndLocalBasePath']['rDriveType'] < len(self.DRIVE_TYPES):
						self.loc_information['VolumeIDAndLocalBasePath']['DriveType'] = self.DRIVE_TYPES[self.loc_information['VolumeIDAndLocalBasePath']['rDriveType']]

					if self.loc_information['VolumeIDAndLocalBasePath']['VolumeLabelOffset'] != 20:
						length = self.loc_information['VolumeIDAndLocalBasePath']['VolumeIDSize'] - self.loc_information['VolumeIDAndLocalBasePath']['VolumeLabelOffset']
						local_index = index + self.loc_information['VolumeIDOffset'] + self.loc_information['VolumeIDAndLocalBasePath']['VolumeLabelOffset']
						self.loc_information['VolumeIDAndLocalBasePath']['VolumeLabel'] = self.clean_line(self.indata[local_index: local_index + length].replace(b'\x00', b''))
					else:
						self.loc_information['VolumeIDAndLocalBasePath']['o_VolumeLabelOffsetUnicode'] = struct.unpack('<i', self.indata[local_index + 16: local_index + 20])[0]
						local_index = index + self.loc_information['VolumeIDOffset'] + self.loc_information['VolumeIDAndLocalBasePath']['o_VolumeLabelOffsetUnicode']
						self.loc_information['VolumeIDAndLocalBasePath']['o_VolumeLabelUnicode'] = struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

				elif self.loc_information['LinkInfoFlags'] & 0x0002:
					if self.loc_information['LinkInfoHeaderSize'] >= 36:
						self.loc_information['o_CommonPathSuffixOffsetUnicode'] = \
								struct.unpack('<i', self.indata[index + 28: index + 32])[0]
						local_index = index + self.loc_information['o_CommonPathSuffixOffsetUnicode']
						self.loc_information['o_CommonPathSuffixUnicode'] = struct.unpack('<i', self.indata[local_index: local_index + 4])[0]
					else:
						local_index = index + self.loc_information['CommonPathSuffixOffset']
						self.loc_information['CommonPathSuffix'] = \
								struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

					local_index = index + self.loc_information['CommonNetworkRelativeLinkOffset']
					self.loc_information['location'] = 'CommonNetworkRelativeLinkAndPathSuffix'
					self.loc_information['CommonNetworkRelativeLinkAndPathSuffix'] = {
						'CommonNetworkRelativeLinkSize':
							struct.unpack('<i', self.indata[local_index + 0: local_index + 4])[0],
						'CommonNetworkRelativeLinkFlags':
							struct.unpack('<i', self.indata[local_index + 4: local_index + 8])[0],
						'NetNameOffset':
							struct.unpack('<i', self.indata[local_index + 8: local_index + 12])[0],
						'DeviceNameOffset':
							struct.unpack('<i', self.indata[local_index + 12: local_index + 16])[0],
						'NetworkProviderType':
							struct.unpack('<i', self.indata[local_index + 16: local_index + 20])[0],
					}

					if self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_NetNameOffset'] > 20:
						self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_NetNameOffsetUnicode'] = \
						struct.unpack('<i', self.indata[local_index + 20: index + 24])[0]
						local_index = index + self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_NetNameOffsetUnicode']
						self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_NetNameOffsetUnicode'] = \
							struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

						self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_DeviceNameOffsetUnicode'] = \
						struct.unpack('<i', self.indata[local_index + 24: index + 28])[0]
						local_index = self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_DeviceNameOffsetUnicode']
						self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_DeviceNameOffsetUnicode'] = \
							struct.unpack('<i', self.indata[local_index: local_index + 4])[0]
					else:
						local_index = index + self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_NetNameOffset']
						self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_NetNameOffset'] = \
							struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

						local_index = self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_DeviceNameOffset']
						self.loc_information['CommonNetworkRelativeLinkAndPathSuffix']['o_DeviceNameOffset'] = \
							struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

				index += (self.loc_information['LinkInfoSize'])

			except Exception as e:
				if self.debug:
					print('Exception parsing Location information: %s' % e)
				return False

			try:
				u_mult = 1
				if self.linkFlag['IsUnicode']:
					u_mult = 2

				if self.linkFlag['HasName']:
					self.data['description'] = self.read_stringData(index, u_mult)

				if self.linkFlag['HasRelativePath']:
					index, self.data['relativePath'] = self.read_stringData(index, u_mult)

				if self.linkFlag['HasWorkingDir']:
					index, self.data['workingDirectory'] = self.read_stringData(index, u_mult)

				if self.linkFlag['HasArguments']:
					index, self.data['commandLineArguments'] = self.read_stringData(index, u_mult)

				if self.linkFlag['HasIconLocation']:
					index, self.data['iconLocation'] = self.read_stringData(index, u_mult)

			except Exception as e:
				if self.debug:
					print('Exception in parsing data: %s' % e)
				return False

			try:
				while index <= len(self.indata) - 10:
					try:
						size = struct.unpack('<I', self.indata[index: index + 4])[0]
						sig = str(hex(struct.unpack('<I', self.indata[index + 4: index + 8])[0]))[2:]
						self.EXTRA_SIGS[sig](index, size)

						index += (size)
					except Exception as e:
						if self.debug:
							print('Exception in EXTRABLOCK Parsing: %s ' % e)
						index = len(self.data)
						break
			except Exception as e:
				if self.debug:
					print('Exception in EXTRABLOCK: %s' % e)

	def parse_environment_block(self, index, size):
		self.extraBlocks['ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK'] = {}
		self.extraBlocks['ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK']['size'] = size
		self.extraBlocks['ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK'][
			'variable_location'] = self.clean_line(self.indata[index + 8: index + 8 + size])

	def parse_console_block(self, index, size):
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'] = {}

	def parse_distributedTracker_block(self, index, size):
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK'] = {}
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['size'] = \
			struct.unpack('<I', self.indata[index + 8: index + 12])[0]
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['version'] = \
			struct.unpack('<I', self.indata[index + 12: index + 16])[0]

		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['machine_identifier'] = self.clean_line(
			self.indata[index + 16: index + 32])

		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['droid_volume_identifier'] = \
			self.to_guid(self.indata[index + 32: index + 48])
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['droid_file_identifier'] = \
			self.to_guid(self.indata[index + 48: index + 64])
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['birth_droid_volume_identifier'] = \
			self.to_guid(self.indata[index + 64: index + 80])
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['birth_droid_file_identifier'] = \
			self.to_guid(self.indata[index + 80: index + 96])

	def parse_codepage_block(self, index, size):
		self.extraBlocks['CONSOLE_CODEPAGE_BLOCK'] = {}

	def parse_specialFolder_block(self, index, size):
		self.extraBlocks['SPECIAL_FOLDER_LOCATION_BLOCK'] = {}

	def parse_darwin_block(self, index, size):
		self.extraBlocks['DARWIN_BLOCK'] = {}

	def parse_icon_block(self, index, size):
		self.extraBlocks['ICON_LOCATION_BLOCK'] = {}

	def parse_shimLayer_block(self, index, size):
		self.extraBlocks['SHIM_LAYER_BLOCK'] = {}

	def parse_metadata_block(self, index, size):
		self.extraBlocks['METADATA_PROPERTIES_BLOCK'] = {}
		self.extraBlocks['METADATA_PROPERTIES_BLOCK']['block_size'] = \
			struct.unpack('<I', self.indata[index: index + 0x04])[0]
		if self.extraBlocks['METADATA_PROPERTIES_BLOCK']['block_size'] > 0x0c:
			offset = 0x08
			count = 1
			while offset + 0x04 <= size:
				s = struct.unpack('<I', self.indata[index + offset: index + offset + 0x04])[0]
				if s == 0x00:
					break;
				self.extraBlocks['METADATA_PROPERTIES_BLOCK']['property_storage_size_{}'.format(count)] = s
				if offset + 0x04 + s <= size and s >= 0x10:
					self.extraBlocks['METADATA_PROPERTIES_BLOCK'][
						'property_storage_format_id_{}'.format(count)] = \
						self.to_guid(self.indata[index + offset + 0x08 : index + offset + 0x18])
					self.extraBlocks['METADATA_PROPERTIES_BLOCK'][
						'property_storage_value_{}'.format(count)] = \
						self.indata[index + offset + 0x18 : index + offset + s].hex()
				offset += s
				count += 1
		

	def parse_knownFolder_block(self, index, size):
		self.extraBlocks['KNOWN_FOLDER_LOCATION_BLOCK'] = {}

	def parse_shellItem_block(self, index, size):
		self.extraBlocks['SHELL_ITEM_IDENTIFIER_BLOCK'] = {}

	def print_lnk_file(self):
		print('Windows Shortcut Information:')
		print('\tLink Flags: %s - (%s)' % (self.format_linkFlags(), self.lnk_header['rlinkFlags']))
		print('\tFile Flags: %s - (%s)' % (self.format_fileFlags(), self.lnk_header['rfileFlags']))
		print('')
		try:
			print('\tCreation Timestamp: %s' % (self.ms_time_to_unix_time(self.lnk_header['creation_time'])))
			print('\tModified Timestamp: %s' % (self.ms_time_to_unix_time(self.lnk_header['modified_time'])))
			print('\tAccessed Timestamp: %s' % (self.ms_time_to_unix_time(self.lnk_header['accessed_time'])))
			print('')
		except:
			print('\tProblem Parsing Timestamps')
		print(
			'\tFile Size: %s (r: %s)' % (str(self.lnk_header['file_size']), str(len(self.indata))))
		print('\tIcon Index: %s ' % (str(self.lnk_header['icon_index'])))
		print('\tWindow Style: %s ' % (str(self.lnk_header['windowstyle'])))
		print('\tHotKey: %s ' % (str(self.lnk_header['hotkey'])))

		print('')

		for rline in self.data:
			print('\t%s: %s' % (rline, self.data[rline]))

		print('')
		print('\tEXTRA BLOCKS:')
		for enabled in self.extraBlocks:
			print('\t\t%s' % enabled)
			for block in self.extraBlocks[enabled]:
				print('\t\t\t[%s] %s' % (block, self.extraBlocks[enabled][block]))

	def ms_time_to_unix_time(self, time):
		return datetime.datetime.fromtimestamp(time / 10000000.0 - 11644473600).strftime('%Y-%m-%d %H:%M:%S')

	def read_string(self, index):
		result = ''
		while self.indata[index] != 0x00:
			result += chr(self.indata[index])
			index += 1
		return result

	def read_stringData(self, index, u_mult):
		string_size = struct.unpack('<H', self.indata[index: index + 2])[0] * u_mult
		string = self.clean_line(self.indata[index + 2: index + 2 + string_size].replace(b'\x00', b''))
		new_index = index + string_size + 2
		return new_index, string

	@staticmethod
	def enabled_flags_to_list(flags):
		enabled = []
		for flag in flags:
			if flags[flag]:
				enabled.append(flag)
		return enabled

	def format_linkFlags(self):
		enabled = self.enabled_flags_to_list(self.linkFlag)
		return ' | '.join(enabled)

	def format_fileFlags(self):
		enabled = self.enabled_flags_to_list(self.fileFlag)
		return ' | '.join(enabled)

	def print_short(self, pjson=False):
		out = ''
		if self.linkFlag['HasRelativePath']:
			out += self.data['relativePath']
		if self.linkFlag['HasArguments']:
			out += ' ' + self.data['commandLineArguments']

		if pjson:
			print(json.dumps({'command': out}))
		else:
			print(out)

	def print_json(self, print_all=False):
		res = {'header': self.lnk_header, 'data': self.data, 'target': self.targets, 'link_info': self.loc_information, 'extra': self.extraBlocks}

		if 'creation_time' in res['header']:
			res['header']['creation_time'] = self.ms_time_to_unix_time(res['header']['creation_time'])
		if 'accessed_time' in res['header']:
			res['header']['accessed_time'] = self.ms_time_to_unix_time(res['header']['accessed_time'])
		if 'modified_time' in res['header']:
			res['header']['modified_time'] = self.ms_time_to_unix_time(res['header']['modified_time'])

		if not print_all:
			res['header'].pop('header_size')
			res['header'].pop('reserved0')
			res['header'].pop('reserved1')
			res['header'].pop('reserved2')
			res['target'].pop('size')
			res['link_info'].pop('LinkInfoSize')
			res['link_info'].pop('LinkInfoHeaderSize')
			res['link_info'].pop('VolumeIDOffset')
			res['link_info'].pop('LocalBasePathOffset')
			res['link_info'].pop('CommonNetworkRelativeLinkOffset')
			res['link_info'].pop('CommonPathSuffixOffset')
			if 'VolumeIDAndLocalBasePath' in res['link_info']:
				res['link_info']['VolumeIDAndLocalBasePath'].pop('VolumeIDSize')
				res['link_info']['VolumeIDAndLocalBasePath'].pop('VolumeLabelOffset')
			if 'CommonNetworkRelativeLinkAndPathSuffix' in res['link_info']:
				res['link_info']['CommonNetworkRelativeLinkAndPathSuffix'].pop('CommonNetworkRelativeLinkSize')
				res['link_info']['CommonNetworkRelativeLinkAndPathSuffix'].pop('NetNameOffset')
				res['link_info']['CommonNetworkRelativeLinkAndPathSuffix'].pop('DeviceNameOffset')

		print(json.dumps(res, indent=4, separators=(',', ': ')))

def test_case(filename):
	with open(filename, 'rb') as file:
		tmp = lnk_file(fhandle=file, debug=True)
		tmp.print_lnk_file()
		# tmp.print_short(True)
		# tmp.print_json()


def main():
	arg_parser = argparse.ArgumentParser(description=__description__)
	arg_parser.add_argument('-f', '--file', dest='file', required=True,
							help='absolute or relative path to the file')
	arg_parser.add_argument('-j', '--json', action='store_true',
							help='print output in JSON')
	arg_parser.add_argument('-d', '--json_debug', action='store_true',
							help='print all extracted data in JSON (i.e. offsets and sizes)')
	arg_parser.add_argument('-D', '--debug', action='store_true',
							help='print debug info')
	args = arg_parser.parse_args()

	with open(args.file, 'rb') as file:
		lnk = lnk_file(fhandle=file, debug=args.debug)
		if args.json:
			lnk.print_json(args.json_debug)
		else:
			lnk.print_lnk_file()


if __name__ == '__main__':
	main()
