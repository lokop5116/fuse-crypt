#include "common.h"
#include "encrypt.c"

#include <cjson/cJSON.h>

#include <stdlib.h>

// serialize our filesystem ->store it as a JSON file between mountings
//
// user can unmount filesystem and not lose data
// otherwise data remains in memory and is effectively useless as a filesystem

// serialize a JSON node
cJSON *serialize_node(Node *node) {
  cJSON *jnode = cJSON_CreateObject();

  // add our Node attributes
  cJSON_AddStringToObject(jnode, "name", node->name);
  cJSON_AddNumberToObject(jnode, "type", node->type);
  cJSON_AddNumberToObject(jnode, "size", node->size);

  // IV needs to be encoded before putting in because fuck you cJSON
  char *iv_b64 = base64_encode(node->iv, AES_IVLEN);
  cJSON_AddStringToObject(jnode, "iv", iv_b64);
  free(iv_b64);

  if (node->type == NODE_FILE) {
    // our data should already be encrypted at this point so we can just pass it
    // through
    cJSON_AddStringToObject(jnode, "content", node->content);
  }

  // add any children nodes
  cJSON *children = cJSON_CreateArray();
  for (int i = 0; i < node->child_count; i++) {
    cJSON_AddItemToArray(children, serialize_node(node->children[i]));
  }
  cJSON_AddItemToObject(jnode, "children", children);

  return jnode;
}

// put our cJSON node onto a .json file
void save_to_disk(const char *filename) {

  cJSON *root_json = serialize_node(root);
  char *json_str = cJSON_Print(root_json);

  FILE *fp = fopen(filename, "w");

  if (fp) {
    fputs(json_str, fp);
    fclose(fp);
  }

  free(json_str);
  cJSON_Delete(root_json);
}

// deserialize - reading filesystem state
Node *deserialize_node(cJSON *jnode, Node *parent) {

  Node *node = calloc(1, sizeof(Node));

  // attributes hat can be copied directly
  strcpy(node->name, cJSON_GetObjectItem(jnode, "name")->valuestring);
  node->type = cJSON_GetObjectItem(jnode, "type")->valueint;
  node->size = cJSON_GetObjectItem(jnode, "size")->valueint;
  node->parent = parent;

  // IV must be decrypted and then copied
  char *iv_str = cJSON_GetObjectItem(jnode, "iv")->valuestring;
  base64_decode(iv_str, node->iv, AES_IVLEN);

  // file node then must decrypt the contents as well
  if (node->type == NODE_FILE) {

    const char *content = cJSON_GetObjectItem(jnode, "content")->valuestring;
    node->content = calloc(1, MAX_CONTENT_SIZE);
    strncpy(node->content, content, MAX_CONTENT_SIZE - 1);
  }

  cJSON *children = cJSON_GetObjectItem(jnode, "children");
  int n = cJSON_GetArraySize(children);

  // children nodes
  for (int i = 0; i < n; i++) {
    cJSON *child_json = cJSON_GetArrayItem(children, i);
    node->children[node->child_count++] = deserialize_node(child_json, node);
  }

  return node;
}

// read our .json file from disk
//
void load_from_disk(const char *filename) {

  FILE *fp = fopen(filename, "r");

  if (!fp) {
    return; // no saved state yet
  }

  // move file pointer to end
  fseek(fp, 0, SEEK_END);

  // length of json file
  long len = ftell(fp);

  // back to beginning
  fseek(fp, 0, SEEK_SET);

  char *data = malloc(len + 1);

  // read our data into buffer
  fread(data, 1, len, fp);
  data[len] = '\0';
  fclose(fp);

  // use cJSON's parse function
  cJSON *root_json = cJSON_Parse(data);
  free(data);

  // use our deserialization function and voila
  if (root_json) {
    root = deserialize_node(root_json, NULL);
    cJSON_Delete(root_json);
  }
}
