zip parser: parse a ZIP file and print out information about its various sections
=================================================================================

ZIP files are a lot more complex than just a bunch of files stuck together
and compressed: file attributes, extensions, encryption, etc. all contribute
to making these files quite complex and prone to having information leaks in
all the encoded data.

Some interesting details you can obtain from a ZIP file:

* Creation, access and modification times - down to the nanosecond if packed
  on Windows systems

* UID and GID of the user that owns a file

* Gaps in the ZIP files where data may be hidden

Usage
-----

The script accepts just a single parameter, the path of the ZIP file:

```
	$ python zip_parser.py <zipfile>
```

Credits
-------

The implementation is based on the ZIP file spec published at https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
