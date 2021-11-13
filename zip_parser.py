#!/usr/bin/env python3
# 
# Parses a ZIP file and print out information about its various sections.
# 
# Usage:
#  python zip_parser.py <zipfile>
# 
# Based on the ZIP file spec published at https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

import binascii
import sys
from datetime import datetime, timedelta

def hexdump(bytes):
  return binascii.hexlify(bytes).decode('utf-8')

def bindump(bytes):
  return bin(int.from_bytes(bytes, byteorder='little'))

def datetime_from_epoch(epoch):
  return datetime.fromtimestamp(epoch)

def datetime_from_win32epoch(win32epoch):
  return datetime(1601, 1, 1, 0, 0, 0) + timedelta(seconds = win32epoch / 1e7)

def zip_parse_extra_fields(data):
  fields = []
  while data:
    field_type = data[0:2]
    field_size = int.from_bytes(data[2:4], byteorder='little')
    field_data = data[4:4+field_size]
    data = data[4+field_size:]
    fields.append((field_type, field_data))
  return fields

def zip_extra_field_printable(parsed_extra_field):
  ret = ''

  if parsed_extra_field[0] == b'\x01\x01':
    return 'Comment: ' + parsed_extra_field[1].decode('utf-8')
  elif parsed_extra_field[0] == b'\x01\x02':
    return 'Internal File Attributes: ' + parsed_extra_field[1].decode('utf-8')
  elif parsed_extra_field[0] == b'\x01\x03':
    return 'External File Attributes: ' + parsed_extra_field[1].decode('utf-8')
  elif parsed_extra_field[0] == b'\x01\x04':
    return 'Windows NT Special Folder: ' + parsed_extra_field[1].decode('utf-8')
  elif parsed_extra_field[0] == b'\x01\x05':
    return 'Windows NT Reserved: ' + parsed_extra_field[1].decode('utf-8')
  elif parsed_extra_field[0] == b'\x01\x06':
    return 'Info-ZIP Unicode Path Extra Field: ' + parsed_extra_field[1].decode('utf-8')
  elif parsed_extra_field[0] == b'\x01\x07':
    return 'Info-ZIP Unicode Comment Extra Field: ' + parsed_extra_field[1].decode('utf-8')
  elif parsed_extra_field[0] == b'\x01\x08':
    return 'Info-ZIP Extended Timestamp Extra Field: ' + parsed_extra_field[1].decode('utf-8')
  elif parsed_extra_field[0] == b'\x55\x54':
    flags = parsed_extra_field[1][0:1]
    modification_time = int.from_bytes(parsed_extra_field[1][1:5], byteorder='little')
    access_time = int.from_bytes(parsed_extra_field[1][5:9], byteorder='little')
    creation_time = int.from_bytes(parsed_extra_field[1][9:13], byteorder='little')

    ret = 'Extended timestamp: Flags: %s, Modification time: %s, Access time: %s, Creatime time: %s' % (hexdump(flags), datetime_from_epoch(modification_time), datetime_from_epoch(access_time), datetime_from_epoch(creation_time))
  elif parsed_extra_field[0] == b'\x75\x78':
    version = int.from_bytes(parsed_extra_field[1][0:1], byteorder='little')
    uid_size = int.from_bytes(parsed_extra_field[1][1:2], byteorder='little')
    uid = int.from_bytes(parsed_extra_field[1][2:2 + uid_size], byteorder='little')
    gid_size = int.from_bytes(parsed_extra_field[1][2 + uid_size : 2 + uid_size + 1], byteorder='little')
    gid = int.from_bytes(parsed_extra_field[1][2 + uid_size + 1: 2 + uid_size + 1 + gid_size], byteorder='little')

    ret = 'UNIX Version: %d, UID (%d bytes): %d , GID (%d bytes): %d' % (version, uid_size, uid, gid_size, gid)
  elif parsed_extra_field[0] == b'\x0a\x00':
    ret = 'NTFS'

    reserved = parsed_extra_field[1][0:4]
    ntfs = parsed_extra_field[1][4:]

    while ntfs:
      tag = ntfs[0:2]
      size = int.from_bytes(ntfs[2:4], byteorder='little')
      data = ntfs[4:4 + size]

      if tag == b'\x01\x00':
        ntfs_modification_time = int.from_bytes(data[0:8], byteorder='little')
        ntfs_access_time = int.from_bytes(data[8:16], byteorder='little')
        ntfs_creation_time = int.from_bytes(data[16:24], byteorder='little')
        ret += ' timestamp, Modification time: %s, Access time: %s, Creation time: %s' % (datetime_from_win32epoch(ntfs_modification_time), datetime_from_win32epoch(ntfs_access_time), datetime_from_win32epoch(ntfs_creation_time))
      else:
        ret += ' Unknown tag: %s, Size: %d, Data: %s' % (hexdump(tag), size, hexdump(data))

      ntfs = ntfs[4 + size:]

    version = int.from_bytes(parsed_extra_field[1][0:1], byteorder='little')
    uid_size = int.from_bytes(parsed_extra_field[1][1:2], byteorder='little')
    uid = int.from_bytes(parsed_extra_field[1][2:2 + uid_size], byteorder='little')
    gid_size = int.from_bytes(parsed_extra_field[1][2 + uid_size : 2 + uid_size + 1], byteorder='little')
    gid = int.from_bytes(parsed_extra_field[1][2 + uid_size + 1: 2 + uid_size + 1 + gid_size], byteorder='little')

  else:
    ret = "Unknown Header ID %s, content is: %s" % (hexdump(parsed_extra_field[0]), parsed_extra_field[1])

  return ret

def parse_file():
  print("[*] ZIP file header")

  version = file.read(2)
  general_purpose_bit_flag = file.read(2)
  compression_method = file.read(2)
  last_mod_file_time = file.read(2)
  last_mod_file_date = file.read(2)
  crc32 = file.read(4)
  compressed_size = file.read(4)
  uncompressed_size = file.read(4)
  filename_length = file.read(2)
  extra_field_length = file.read(2)

  filename = file.read(int.from_bytes(filename_length, byteorder='little')).decode('utf-8')

  extra_fields = file.read(int.from_bytes(extra_field_length, byteorder='little'))

  print("[*] Version needed to extract: %s" % version)
  print("[*] General purpose bit flag: %s" % bindump(general_purpose_bit_flag))
  print("[*] Compression method: %s" % compression_method)
  print("[*] Last mod file time: %s" % last_mod_file_time)
  print("[*] Last mod file date: %s" % last_mod_file_date)
  print("[*] CRC32: %s" % crc32)
  print("[*] Compressed size: %s" % int.from_bytes(compressed_size, byteorder='little'))
  print("[*] Uncompressed size: %s" % int.from_bytes(uncompressed_size, byteorder='little'))
  print("[*] Filename length: %s" % int.from_bytes(filename_length, byteorder='little'))
  print("[*] Extra field length: %s" % int.from_bytes(extra_field_length, byteorder='little'))
  print("[*] Filename: %s" % filename)

  parsed_extra_fields = zip_parse_extra_fields(extra_fields)

  for idx, parsed_extra_field in enumerate(parsed_extra_fields):
    print("[*]\tExtra field %d, Header ID: %s" % (idx, hexdump(parsed_extra_field[0])))

    printable = zip_extra_field_printable(parsed_extra_field)
    print('[*]\t\t' + printable)

  # Skip file data
  file_data = file.read(int.from_bytes(compressed_size, byteorder='little'))

  # Get encryption header, if file is encrypted

  if int.from_bytes(general_purpose_bit_flag, byteorder='little') & 0x0001 == 0x0001:
    encryption_header = file_data[0:12]
    print("[*] Encryption header: %s" % encryption_header)
  else:
    print("[*] File is not encrypted")

  if int.from_bytes(general_purpose_bit_flag, byteorder='little') & 0x0008 == 0x0008:
    print("[*] Data descriptor found")

    data_crc32 = file.read(4)


    if data_crc32 == b'PK\x07\x08':
      data_crc32 = file.read(4)

    data_compressed_size = file.read(4)
    data_uncompressed_size = file.read(4)

    print("[*] Data CRC32: %s" % data_crc32)
    print("[*] Data compressed size: %s" % int.from_bytes(data_compressed_size, byteorder='little'))
    print("[*] Data uncompressed size: %s" % int.from_bytes(data_uncompressed_size, byteorder='little'))

  else:
    print("[*] No data descriptor found")

def parse_central_directory():
  print("[*] ZIP central directory header")

  version_made_by = file.read(2)
  version_needed_to_extract = file.read(2)
  general_purpose_bit_flag = file.read(2)
  compression_method = file.read(2)
  last_mod_file_time = file.read(2)
  last_mod_file_date = file.read(2)
  crc32 = file.read(4)
  compressed_size = file.read(4)
  uncompressed_size = file.read(4)
  filename_length = file.read(2)
  extra_field_length = file.read(2)
  file_comment_length = file.read(2)
  disk_number_start = file.read(2)
  internal_file_attributes = file.read(2)
  external_file_attributes = file.read(4)
  relative_offset_of_local_header = file.read(4)
  filename = file.read(int.from_bytes(filename_length, byteorder='little')).decode('utf-8')
  extra_fields = file.read(int.from_bytes(extra_field_length, byteorder='little'))
  file_comment = file.read(int.from_bytes(file_comment_length, byteorder='little'))

  print("[*] Version made by: %s" % version_made_by)
  print("[*] Version needed to extract: %s" % version_needed_to_extract)
  print("[*] General purpose bit flag: %s" % bindump(general_purpose_bit_flag))
  print("[*] Compression method: %s" % compression_method)
  print("[*] Last mod file time: %s" % last_mod_file_time)
  print("[*] Last mod file date: %s" % last_mod_file_date)
  print("[*] CRC32: %s" % crc32)
  print("[*] Compressed size: %s" % int.from_bytes(compressed_size, byteorder='little'))
  print("[*] Uncompressed size: %s" % int.from_bytes(uncompressed_size, byteorder='little'))
  print("[*] Filename length: %s" % int.from_bytes(filename_length, byteorder='little'))
  print("[*] Extra field length: %s" % int.from_bytes(extra_field_length, byteorder='little'))
  print("[*] File comment length: %s" % int.from_bytes(file_comment_length, byteorder='little'))
  print("[*] Disk number start: %s" % int.from_bytes(disk_number_start, byteorder='little'))
  print("[*] Internal file attributes: %s" % internal_file_attributes)
  print("[*] External file attributes: %s" % external_file_attributes)
  print("[*] Relative offset of local header: %s" % int.from_bytes(relative_offset_of_local_header, byteorder='little'))
  print("[*] Filename: %s" % filename)

  parsed_extra_fields = zip_parse_extra_fields(extra_fields)

  for idx, parsed_extra_field in enumerate(parsed_extra_fields):
    print("[*]\tExtra field %d, Header ID: %s" % (idx, hexdump(parsed_extra_field[0])))

    printable = zip_extra_field_printable(parsed_extra_field)
    print('[*]\t\t' + printable)

  print("[*] File comment: %s" % file_comment)

def parse_end_central_directory():
  print("[*] ZIP end central directory header")

  disk_number_start = file.read(2)
  disk_number_end = file.read(2)
  disk_entries_start = file.read(2)
  disk_entries_end = file.read(2)
  central_directory_size = file.read(4)
  central_directory_offset = file.read(4)
  comment_length = file.read(2)

  print("[*] Disk number start: %s" % int.from_bytes(disk_number_start, byteorder='little'))
  print("[*] Disk number end: %s" % int.from_bytes(disk_number_end, byteorder='little'))
  print("[*] Disk entries start: %s" % int.from_bytes(disk_entries_start, byteorder='little'))
  print("[*] Disk entries end: %s" % int.from_bytes(disk_entries_end, byteorder='little'))
  print("[*] Central directory size: %s" % int.from_bytes(central_directory_size, byteorder='little'))
  print("[*] Central directory offset: %s" % int.from_bytes(central_directory_offset, byteorder='little'))
  print("[*] Comment length: %s" % int.from_bytes(comment_length, byteorder='little'))

filename = sys.argv[1]

file = open(filename, "rb")

signature = ''

while 1:
  signature = file.read(4)

  if signature == b'PK\x03\x04':
    parse_file()
  elif signature == b'PK\x01\x02':
    parse_central_directory()
  elif signature == b'PK\x05\x06':
    parse_end_central_directory()
  elif signature == b'':
    break

  else:
    print("Unknown signature: %s" % (signature))
    break

  print()

file.close()
