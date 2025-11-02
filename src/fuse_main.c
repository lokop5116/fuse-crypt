// version of FUSE to use, must give to use latest version otherwise defaults to
// 26 which is bad
#define FUSE_USE_VERSION 31

// make sure to change this if you are trying to install this for yourself
#define SAVE_PATH "/home/test/Projects/FUSE/state/fs_state.json"

// includes
#include "common.h"
#include "serialize.c"
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
// ####################

// definition of root, declared in common.h
Node *root = NULL;

// name is self explanatory
static Node *find_node(const char *path) {

  if (strcmp(path, "/") == 0) {
    return root;
  }

  if (strlen(path) > MAX_PATH_LEN) {
    printf("Path is too long\n");
    return NULL;
  }
  char tmp[MAX_PATH_LEN];

  strcpy(tmp, path);
  char *token = strtok(tmp, "/");

  Node *cur = root;

  while (token && cur) {
    Node *next = NULL;

    // iterate over all children nodes, check if child node's name is the same
    // as whatever token we're at in path, if yes then go to it
    for (int i = 0; i < cur->child_count; i++) {

      if (strcmp(cur->children[i]->name, token) == 0) {
        next = cur->children[i];
        break;
      }
    }

    // no child with matching name, soething went wrong.
    // Ideally shouldn't ever pass that condition
    if (!next) {
      return NULL;
    }

    cur = next;
    token = strtok(NULL, "/");
  }

  // return the node
  return cur;
}

// find parent directory
static Node *get_parent_dir(const char *path, char *name_out) {
  if (strlen(path) > MAX_PATH_LEN) {
    printf("Path too long, can't get parent");
    return NULL;
  }

  char tmp[MAX_PATH_LEN];
  strcpy(tmp, path);

  char *last_slash = strrchr(tmp, '/');

  if (last_slash == NULL) {
    return NULL;
  }

  if (last_slash == tmp) {

    // if its in root directory i.e. /filename
    strcpy(name_out, last_slash + 1);
  } else {

    // copy name of last node ( whatever comes after last / ) and terminate
    // string at last /
    strcpy(name_out, last_slash + 1);
    *last_slash = '\0';
  }

  if (last_slash == tmp) {

    // for nodes in root directory
    return root;
  }
  return find_node(tmp);
}

// initialize the root node
static void init_root() {
  root = calloc(1, sizeof(Node));
  strcpy(root->name, "/");
  root->type = NODE_DIR;
}

int my_getattr(const char *path, struct stat *stbuf,
               struct fuse_file_info *fi) {

  // stat is a predefined struct, we pass pointer to stbuf which is an instance
  // of stat stat stands for status I think? status of node ( file/directory )
  // each value must be set accordingly, like mode, size etc etc according to
  // node contents

  // just initialize the entire fucking thing to 0
  memset(stbuf, 0, sizeof(struct stat));
  Node *node = find_node(path);

  if (node == NULL) {

    // no such file/directory error code, found in
    // /usr/include/asm-generic/errno-base.h
    return -ENOENT;
  }

  if (node->type == NODE_DIR) {

    stbuf->st_mode = S_IFDIR | 0755; // code for directory
    stbuf->st_nlink = 2; // link count - number of hard links pointing
  } else {

    stbuf->st_mode = S_IFREG | 0666; // code for regular
    stbuf->st_nlink = 1;             // line count
    stbuf->st_size = node->size;     // file size
  }
  return 0;
}

// read/access a directory - like ls etc etc
int my_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi,
               enum fuse_readdir_flags flags) {
  Node *dir = find_node(path);

  if (!dir || dir->type != NODE_DIR) {
    // no such entry of a directory
    return -ENOENT;
  }

  filler(buf, ".", NULL, 0, 0);  // each directory must contain '.' and '..' as
                                 // the directory itself and its parent
  filler(buf, "..", NULL, 0, 0); // not stored as nodes only added via filler

  // iterate over children and add them as entries
  for (int i = 0; i < dir->child_count; i++) {
    filler(buf, dir->children[i]->name, NULL, 0, 0);
  }

  return 0;
}

// add a directory node
int my_mkdir(const char *path, mode_t mode) {

  char name[MAX_NAME_LEN];
  Node *parent = get_parent_dir(
      path, name); // gets parent directory of whatever directory you're making

  if (!parent || parent->type != NODE_DIR) {

    // parent type is not a directory or parent does not exist
    // then error no entry :D
    return -ENOENT;
  }

  for (int i = 0; i < parent->child_count; i++) {

    // iterate over children and see if it already exists
    if (strcmp(parent->children[i]->name, name) == 0) {
      return -EEXIST; // error already exists
    }
  }

  // create your node and assign stuff blah blah
  //
  Node *dir = calloc(1, sizeof(Node));
  strcpy(dir->name, name);

  dir->type = NODE_DIR; // node type must be directory
  dir->parent = parent;

  parent->children[parent->child_count++] = dir;

  // since there is a change in filesystem structure we
  // save to json file again
  save_to_disk(SAVE_PATH);

  return 0;
}

// removing directory
int my_rmdir(const char *path) {

  Node *dir = find_node(path);

  if (!dir || dir->type != NODE_DIR) {
    // directory does not exist
    return -ENOENT;
  }

  if (dir->child_count > 0) {
    // directory not empty hence cannot delete, must delete recursively
    return -ENOTEMPTY;
  }

  Node *parent = dir->parent;

  for (int i = 0; i < parent->child_count; i++) {

    // iterate over chidren till you find your directory to remove
    if (parent->children[i] == dir) {

      for (int j = i; j < parent->child_count - 1; j++) {
        parent->children[j] = parent->children[j + 1];
      }
      parent->child_count--;
      break;
    }
  }

  // free the node because memory management
  free(dir);
  save_to_disk(SAVE_PATH);
  return 0;
}

// creating file - touch etc etc
int my_create(const char *path, mode_t mode, struct fuse_file_info *fi) {

  char name[MAX_NAME_LEN];
  Node *parent = get_parent_dir(path, name);

  if (!parent || parent->type != NODE_DIR) {
    return -ENOENT;
  }

  for (int i = 0; i < parent->child_count; i++) {
    if (strcmp(parent->children[i]->name, name) == 0) {
      return -EEXIST;
    }
  }

  // allocate memory and assign each field
  Node *file = calloc(1, sizeof(Node));
  strcpy(file->name, name);

  file->type = NODE_FILE;
  file->parent = parent;
  file->content = calloc(1, MAX_CONTENT_SIZE);
  file->size = 0;

  // Initiation Vector/Nonce must be a randomly generated 16 bit binary array
  // stored upon creation
  // RAND_bytes provided by OpenSSL
  RAND_bytes(file->iv, AES_IVLEN);

  // increase child count and save changes to disk
  parent->children[parent->child_count++] = file;
  save_to_disk(SAVE_PATH);
  return 0;
}

// deleting files - rm etc
int my_unlink(const char *path) {

  Node *file = find_node(path);

  if (!file || file->type != NODE_FILE) {
    return -ENOENT;
  }

  Node *parent = file->parent;

  for (int i = 0; i < parent->child_count; i++) {

    if (parent->children[i] == file) {

      // iterate over children and find your file, shift everythign else
      for (int j = i; j < parent->child_count - 1; j++) {
        parent->children[j] = parent->children[j + 1];
      }

      parent->child_count--;
      break;
    }
  }

  // free file and file contents and save state
  free(file->content);
  free(file);
  save_to_disk(SAVE_PATH);
  return 0;
}

// reading file - cat tail head etc
int my_read(const char *path, char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi) {

  // function returns the number of bytes read
  //
  Node *file = find_node(path);

  if (!file || file->type != NODE_FILE) {
    return -ENOENT;
  }

  // file offset is greater than file size, nothing to read then 0 bytes read
  if (offset >= file->size) {
    return 0;
  }

  // if offset is too great and cannot read 'size' number of bytes then read
  // whatever we can
  if (offset + size > file->size) {
    size = file->size - offset;
  }

  // buffer to contain decrypted contents
  unsigned char decbuf[MAX_CONTENT_SIZE];

  int dec_len = decrypt_buffer((unsigned char *)file->content, file->size,
                               decbuf, file->iv);

  if (dec_len < 0) {
    // IO error
    return -EIO;
  }

  // make sure offset and size are within decrypted data's bounds
  if (offset >= dec_len) {
    return 0;
  }
  if (offset + size > dec_len) {
    size = dec_len - offset;
  }

  memcpy(buf, decbuf + offset, size);
  return size;
}

// write to file
int my_write(const char *path, const char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi) {

  Node *file = find_node(path);

  if (!file || file->type != NODE_FILE) {
    return -ENOENT;
  }

  if (offset + size > MAX_CONTENT_SIZE) {

    // we have defined maximum size to 4KB anything bigger is not allowed
    return -EFBIG;
  }

  // buffer to stored encrypted data
  unsigned char encbuf[MAX_CONTENT_SIZE];

  // the encryption magic
  int enc_len = encrypt_buffer((unsigned char *)buf, size, encbuf, file->iv);

  if (enc_len < 0) {

    // nothing goot encrypted IO error
    return -EIO;
  }

  // set file size, copy to contents and save state
  memcpy(file->content + offset, encbuf, enc_len);
  file->size = enc_len;
  save_to_disk(SAVE_PATH);
  return size;
}

// whenever file changes size - writing beyong EOF
int my_truncate(const char *path, off_t size, struct fuse_file_info *fi) {

  Node *file = find_node(path);

  if (!file || file->type != NODE_FILE) {
    return -ENOENT;
  }

  if (size > MAX_CONTENT_SIZE) {
    return -EFBIG;
  }

  if (size < file->size) {
    memset(file->content + size, 0, file->size - size);
  }

  // just some checks and changing the new file size
  // and save state
  file->size = size;
  save_to_disk(SAVE_PATH);
  return 0;
}

// exiting file system and saving state once more
void my_destroy(void *private_data) {

  printf("Filesystem is being destroyed - saving state.\n");
  save_to_disk(SAVE_PATH);
}

// main struct of fuse operatiosn
// all FUSE operations are assigned functions here
static struct fuse_operations myOperations = {
    .getattr = my_getattr,
    .readdir = my_readdir,
    .read = my_read,
    .write = my_write,
    .truncate = my_truncate,
    .create = my_create,
    .unlink = my_unlink,
    .mkdir = my_mkdir,
    .rmdir = my_rmdir,
    .destroy = my_destroy,
};

int main(int argc, char *argv[]) {

  init_encryption();
  init_root();

  // if file state already exists, load from there
  load_from_disk(SAVE_PATH);

  int result = fuse_main(argc, argv, &myOperations, NULL);

  return result;
}
