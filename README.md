
ASP.NET Crypter (AspNetCrypter)
-------------------------------

It's a small tool to decrypt the ASP.NET protected data offline. The crypto code is copied from the Microsoft's [reference source repository](https://github.com/Microsoft/referencesource). For now it supports only owin.cookies, but please create an issue if you would like to have another part of ASP.NET decrypted. The command line looks as follows:

```
AspNetCrypter v0.0.1.0 - a tool for decryption ASP.NET protected data
Copyright (C) 2016 Sebastian Solnica (@lowleveldesign)

Usage: aspnetcrypter [OPTIONS] encrypteddata

Options:
      --vk=VALUE             the validation key (in hex)
      --dk=VALUE             the decryption key (in hex)
  -p, --purpose=VALUE        the encryption context
                               (currently only: owin.cookie)
      --base64               data is provided in base64 format (otherwise we
                               assume hex)
  -h, --help                 Show this message and exit
  -?                         Show this message and exit
```

Notice, you need to provide the master keys for encryption and validation. An example call might look as follows:

```
aspnetcrypter --dk=0xa5e27...281146d52 --vk=0x507de...34e29a820f6 --purpose=owin.cookie --base64 i1movjk3P...H0FEiSSYxvAy0HY6bIGJNbQ

0000: 03 00 00 00 11 41 70 70 6c 69 63 61 74 69 6f 6e  .....Application
0010: 43 6f 6f 6b 69 65 01 00 01 00 04 00 00 00 44 68  Cookie........Dh
0020: 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 78 6d  ttp://schemas.xm
0030: 6c 73 6f 61 70 2e 6f 72 67 2f 77 73 2f 32 30 30  lsoap.org/ws/200
0040: 35 2f 30 35 2f 69 64 65 6e 74 69 74 79 2f 63 6c  5/05/identity/cl
0050: 61 69 6d 73 2f 6e 61 6d 65 69 64 65 6e 74 69 66  aims/nameidentif
0060: 69 65 72 24 31 64 35 31 62 32 34 63 2d 66 35 65  ier.1d51b24c-f5e
0070: 61 2d 34 61 33 62 2d 39 39 39 65 2d 63 35 37 31  a-4a3b-999e-c571
0080: 61 39 34 31 30 63 63 64 01 00 01 00 01 00 01 00  a9410ccd........
0090: 0d 74 65 73 74 40 74 65 73 74 2e 63 6f 6d 01 00  .test@test.com..
00a0: 01 00 01 00 51 68 74 74 70 3a 2f 2f 73 63 68 65  ....Qhttp://sche
00b0: 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f  mas.microsoft.co
00c0: 6d 2f 61 63 63 65 73 73 63 6f 6e 74 72 6f 6c 73  m/accesscontrols
00d0: 65 72 76 69 63 65 2f 32 30 31 30 2f 30 37 2f 63  ervice/2010/07/c
00e0: 6c 61 69 6d 73 2f 69 64 65 6e 74 69 74 79 70 72  laims/identitypr
00f0: 6f 76 69 64 65 72 10 41 53 50 2e 4e 45 54 20 49  ovider.ASP.NET.I
0100: 64 65 6e 74 69 74 79 01 00 01 00 01 00 1d 41 73  dentity.......As
0110: 70 4e 65 74 2e 49 64 65 6e 74 69 74 79 2e 53 65  pNet.Identity.Se
0120: 63 75 72 69 74 79 53 74 61 6d 70 24 36 33 62 61  curityStamp.63ba
0130: 39 65 62 33 2d 33 66 64 38 2d 34 31 36 35 2d 39  9eb3-3fd8-4165-9
0140: 32 34 33 2d 38 37 33 62 64 33 66 62 64 34 35 39  243-873bd3fbd459
0150: 01 00 01 00 01 00 00 00 00 00 01 00 00 00 02 00  ................
0160: 00 00 08 2e 65 78 70 69 72 65 73 1d 54 75 65 2c  ....expires.Tue,
0170: 20 30 36 20 44 65 63 20 32 30 31 36 20 31 35 3a  .06.Dec.2016.15:
0180: 30 34 3a 33 31 20 47 4d 54 07 2e 69 73 73 75 65  04:31.GMT..issue
0190: 64 1d 54 75 65 2c 20 32 32 20 4e 6f 76 20 32 30  d.Tue,.22.Nov.20
01a0: 31 36 20 31 35 3a 30 34 3a 33 31 20 47 4d 54     16.15:04:31.GMT
```

ASP.NET Key Derive Tool (AspNetDerive)
-------------------------------------

A tool to calculate the derived ASP.NET keys, based on a master key. The command line looks as follows:

```
AspNetDerive v1.0.0.0 - AspNetDerive - a tool to create the derivative ASP.NET keys
Copyright c 2016 Sebastian Solnica (@lowleveldesign)

Usage: aspnetderive [OPTIONS]

Options:
  -k, --key=VALUE            the validation key (in hex)
  -c, --context=VALUE        the context
  -l, --labels=VALUE         the labels, separated by commas
  -h, --help                 show this message and exit
  -?                         show this message and exit
```

Example usage:

```
PS Debug> .\AspNetDerive.exe -k 1726E744C1FF4A6E84A1B511CDDADD10A1AB082044238A10533F8BBB87201926 -c "MachineKeyDerivation" -l "IsolateApps: /"
0000: f2 e0 94 2f 79 0a d1 bb 01 eb 90 50 5c 8b b8 c0  oa./y.N».ë.P\..A
0010: f5 28 41 9b bc fb 6a e2 42 cc cc 7b 51 52 53 8c  o(A..ujâBII{QRS.
```
