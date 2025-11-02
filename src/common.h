// common type declaration/ macros etc etc

#ifndef COMMON_NODE_DEF
#define COMMON_NODE_DEF

// defined macros, mostly regarding limits for file sizes, contents etc etc
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define MAX_FILES 24
#define MAX_NAME_LEN 256
#define MAX_CONTENT_SIZE 4096
#define MAX_PATH_LEN 500
// #######################

// encryption stuff
#define AES_KEYLEN 32
#define AES_IVLEN 16
#define PBKDF2_ITER 100 // keep this small cause performance :(

// our filesystem is designed as a tree-like structure
// each node can have two types, either a file or a directory
// enumerate the two types
typedef enum { NODE_FILE, NODE_DIR } NodeType;

// struct definition for our Nodes
typedef struct Node {
  char name[MAX_NAME_LEN]; // Node name
  NodeType type;           // type -> directory or file
  char *content;           // contents of file ( only initialized if type->file)
  unsigned char iv[16];    // initiation vector
  size_t size;
  struct Node *parent;
  struct Node *children[MAX_FILES];
  int child_count;
} Node;

// Declare root node (shared)
extern Node *root;

#endif // FS_H
