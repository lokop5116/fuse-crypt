#/bin/sh
# echo $(gcc src/fuse_main.c -o out/fuse -D_FILE_OFFSET_BITS=64)

export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig

echo $(gcc -Wall src/fuse_main.c -D_FILE_OFFSET_BITS=64 $(pkg-config fuse3 --cflags --libs) -o out/fuse_main -I/usr/include/ -lcjson -lcrypto)

echo 'Build completed'
