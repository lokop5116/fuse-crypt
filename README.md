# FUSE-crypt
A FUSE filesystem that uses OpenSSL for encryption and saves state in a JSON file

## Features
Mount your own filesystem from a mounting point, any created files are encrypted using AES 256 CTR encryption. The state of filesystem is stored in a JSON file between mounts.

## Dependencies

- [cJSON](https://github.com/DaveGamble/cJSON)
- [OpenSSL](https://github.com/openssl/openssl)
- [libfuse](https://github.com/libfuse/libfuse)

## Installation

> [!caution]
> Works only on Linux based systems.

Clone the repository and go into fuse_main.c and edit save path to whatever you want -

```bash
git clone https://github.com/lokop5116/fuse-crypt
cd fuse-crypt
cd src
```

Inside fuse_main.c -

```c
// must change this to what you want
#define SAVE_PATH "/home/test/Projects/FUSE/state/fs_state.json"
```

Run building script -

```c
cd ..
chmod +x build.sh
./build.sh
```

Executable should be present in fuse-crypt/out directory

## Usage 

To mount a filesystem run-

```bash
./fuse_man [directory] {-f flag to run it in foreground}
```

While mounting you must enter a password which will be used for encrypting/ decrypting all data that you read/write.

It is important that the password you enter must stay consistent between mountings otherwise data you read will be garbled and any data written to file will use this for encryption.

Now this directory will act as the root of our own new filesystem, you can enter from this mounting point and create files/ directories.

To dismount, from another terminal run-

```bash
fusermount3 -u [mounting_directory]
```

Make sure no other terminal is currently in the filesystem or any file within it is open.

## Implementation

Only following FUSE functions have been implemented, the filesystem supports only basic file creation deletions + directories.

```bash
.getattr
.readdir
.read
.write
.truncate
.create
.unlink
.mkdir
.rmdir
.destroy
```
