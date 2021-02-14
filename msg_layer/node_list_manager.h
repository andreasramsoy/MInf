#ifndef __POPCORN_NODE_LIST_MANAGER_H__
#define __POPCORN_NODE_LIST_MANAGER_H__

/*
    This file, the node_list_manager.h, is responsible for manipluating the
    node list specified in node_list.h
*/

#include "node_list.h"

#define COMMAND_BUFFER_SIZE 200 //unlikely to come close to this for adjusting popcorn nodes
#define BOOL_TRUE_RETURN_STRING "1"
#define BOOL_FALSE_RETURN_STRING "0"

char output_buffer[COMMAND_BUFFER_SIZE];

/**
 * Info on a given node. Returns NULL if it does not exist
 * @param index
 * @return void however the output_buffer is filled with pointer to a node, NULL if no node exists
*/
void node_get(int index) {
    struct message_node* node = get_node(index);
    //copy the desired output to the buffer
    sprintf(output_buffer, "???.???.?.? %s", protocol_to_string(node->protocol));
}

/**
 * Checks if a node exists. Checks that a node exists at this index
 * @param int index of the node that it is checking
 * @return void however the output_buffer is filled with bool exists true if there is a node (path to the node is not null)
*/
void node_exists(int index) {
    if (get_node(index)) strcpy(output_buffer, BOOL_TRUE_RETURN_STRING);
    else strcpy(output_buffer, BOOL_FALSE_RETURN_STRING);
}

/**
 * Adds a new node to the node list.
 * @param char* address address of the node
 * @param char* protocol the protocol to be used for the node
 * @return void however the output_buffer is filled with the index of the newly created node in the node list (-1 if it failed)
*/
void node_add(char* address_string, char* protocol_string) {
    //convert values that can be used in the popcorn messaging layer
    enum protocol_t protocol = string_to_protocol(protocol_string);

    uint32_t address = in_aton(address_string);

    //using the values create a node and add it to the list
    struct message_node* node = create_node(address, protocol);
    if (node != NULL) {
        sprintf(output_buffer, "%d", add_node(node));
    }
    else strcpy(output_buffer, "-1");
}

/**
 * Kills the connection and removes the given node. Destroys the connection to the given node, frees the memory that 
 * it used and then deletes the pointer in the node list (replaced with a NULL pointer). Removing a node will not effect 
 * any of the other nodes or the indices used to access them.
 * @param int index of the node to be accessed
 * @return void however the output_buffer is filled with true if successful false if not
*/
void node_remove(int index) {
    if (!get_node(index)) strcpy(output_buffer, BOOL_FALSE_RETURN_STRING);
    else {
        remove_node(index);
        strcpy(output_buffer, BOOL_TRUE_RETURN_STRING);
    }
}

/**
 * Fetches the address of the node.
 * @param int index the index of the node in the node list
 * @param char *address[] string that the result will be placed in
*/
void node_get_address(int index, char address[INET_ADDRSTRLEN]) {
    if (!get_node(index)) printk(KERN_ERR "Failed to get the node address, the address variable has not been updated and so has it's previous value");
    else {
        uint32_t ip = get_node(index)->address;

        //convert to string then return in the string passed by reference
        sprintf(address, "%u.%u.%u.%u", ip & 0xFF, (ip>>8) & 0xFF, (ip>>16) & 0xFF, (ip>>24) & 0xFF);
    }
}

/**
 * Fetches the protocol used in the given node.
 * @param int index the index of the node in the node list
 * @return void however the output_buffer is filled with the protocol used as a string
*/
char* node_get_protocol(int index) {
    enum protocol_t protocol;
    if (!get_node(index)) return "Node does not exist";
    protocol = get_node(index)->protocol;
    if (protocol == TCP) return "TCP";
    else if (protocol == RDMA) return "RDMA";
    else return "Unknown protocol, has a new one been added?";
}

/**
 * Updates the protocol of the node requested.
 * @param int index the index of the node to be updated
 * @param char* protocol the protocol to be updated to
 * @return void however the output_buffer is filled with bool success
*/
void node_update_protocol(int index, char* protocol) {
    if (!get_node(index)) strcpy(output_buffer, BOOL_FALSE_RETURN_STRING);
    else {
        disable_node(index); //tear down existing connection
        get_node(index)->protocol = string_to_protocol(protocol); //change the protocol
        if (enable_node(index)) strcpy(output_buffer, BOOL_TRUE_RETURN_STRING);
        else strcpy(output_buffer, BOOL_FALSE_RETURN_STRING);
    }
}

/**
 * Finds the index of a node in the node list. Performs a linear search to find a node that has the given address
 * Note that this function should be called as infrequently as possible as it is O(n). The function is useful to have
 * but save the indices of the nodes instead as they should not change while popcorn is loaded (they may change when reloaded
 * or when the node_load function is called).
 * @param char[] address
 * @return int index index of the node with the given address
*/
/*int node_find(char* address) {
    int found_at;
    int i;
    struct message_node* node;
    uint32_t search_term = address_string_to_int(address);

    found_at = -1;

    for (i = 0; i < after_last_node_index && found_at == -1; i++) {
        node = get_node(i);
        if (node != NULL) { //some may be null so needed before dereference
            if (node->address == search_term) {
                found_at = i; //record position
            }
        }
    }
    return found_at; //if nothing was found then this will be -1
}*/

/**
 * Reloads the node list to match that of the provided file. Tears down connections to all nodes, attempts to parse the file 
 * provided and create a node list from it. If successful then the new node list is saved to the node list location and this 
 * node list continues to be used. If it fails then popcorn reloads the previously used file for the node list to re-establish 
 * the old connections. The file at the address provided will never be altered (opened read-only) but the popcorn node list 
 * file will be altered if successful.
 * @param char* address address of new node list file to be loaded
 * @return void however the output_buffer is filled with bool success
*/
void node_load(char* address) {
    //load the connections
    /////////////////////////////////////load_list(address);
}

/**
 * Gives the highest indexed node.
 * @return void however the output_buffer is filled with the highest index of a node that exists
*/
void node_highest_index(void) {
    sprintf(output_buffer, "%d", after_last_node_index - 1);
}

/**
 * Saves the current configuration so that when booting occurs this is the configuration
*/
void node_save(void) {
    save_to_file();
}
#endif