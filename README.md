# Small Home Made File Encryption
## Description
Lightweight compression and encryption tool for files and directories.

Folder are archived and compressed using tar.gz, the are encrypted by libsodium with XChaCha20-Poly1305

## Installation 
```bash
git clone https://github.com/JoelInf2430/SHMFencryption.git
cd SHMFencryption
make 
sudo make install
cd .. && rm -rf SHMFencryption

```
## Usage: shmfe [OPTION]...
```bash
  -h, --help           Print help and exit
  -V, --version        Print version and exit
  -i, --input=STRING   Path to the input file
  -o, --output=STRING  Path to the output file
  -e, --encrypt        Enable encryption mode  (default=off)
  -d, --decrypt        Enable decryption mode  (default=off)
  -r, --remove_input   Remove original input file/folder after successful
                         operation  (default=off)
  Encrypt and Compress from path   :   shmfe -ei <PATH>
  Decrypt and Decompress from path :   shmfe -di <PATH>
```

## Uninstalling (without Makefile)
```bash
sudo rm /usr/local/bin/shmfe
```
