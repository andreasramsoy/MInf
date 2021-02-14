#ifndef __POPCORN_NODE_LIST_H__
#define __POPCORN_NODE_LIST_H__


//#define POPCORN_SOCK_ON
//#DEFINE POPCORN_RDMA_ON

/*
 * This specifies the structure of the node list and the basic functions
 * to interact with it
 *
 * 
 * This file takes some parts from the old common.h:
 * Copyright (C) 2017 jackchuang <jackchuang@echo3>
 *
 * Distributed under terms of the MIT license.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <stdbool.h>
#include <popcorn/pcn_kmsg.h>
#include <popcorn/bundle.h>
#include <popcorn/debug.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>

#include "message_node.h"

#define NODE_LIST_FILE_ADDRESS "node_list_file.csv" ///////////////////////////////////update this, find appropriate place for this file to be
#define MAX_FILE_LINE_LENGTH 2048

struct node_list* root_node_list; //Do not access directly! Use get_node(i) function

int my_nid;

int after_last_node_index = 0;

/* function to access the node_list safely, will return 1 if invalid request
   Also allows for changes in data structure (list to avoid limit of 64 nodes) */
struct message_node* get_node(int index) {
	int list_number;
	int i;
	struct node_list* list = root_node_list;
	
	#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(index >= after_last_node_index); //node doesn't exist
	#endif
	
	//move to the appropriate list
	//List number:       index / MAX_NUM_NODES_PER_LIST
	//Index within list: index % MAX_NUM_NODES_PER_LIST
	list_number = index / MAX_NUM_NODES_PER_LIST;
	for (i = 0; i < list_number; i++) {
		#ifdef CONFIG_POPCORN_CHECK_SANITY
				BUG_ON(list->next_list == NULL); //a list must have been removed without deleting the pointer or updating the length variable
		#endif
		list = list->next_list; //move to next list
	}
	
	//should be on correct list now just directly return the node
	
	#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(list->nodes[index % MAX_NUM_NODES_PER_LIST] == NULL); //a list must have been removed without deleting the pointer or updating the length variable
	#endif
	return list->nodes[index % MAX_NUM_NODES_PER_LIST];
}

/**
 * Initialises handlers and queues
 * @param int index of the node that is to be initialised
 */
bool setup_handlers(struct message_node* node) {
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////need to set i

}

/**
 * Creates, allocates space and returns a pointer to a node. This function is separate from the add_node, remove_node,
 * etc. so that if the structure of the nodes change then only this function needs to be changed
 * @param uint32_t address the address of new node
 * @param protocol_t protocol the protocol that the new node should use
 * @return message_node* node pointer to the new node
*/
struct message_node* create_node(uint32_t address_p, struct pcn_kmsg_transport* transport) {
    bool success;

    struct message_node* node = kmalloc(sizeof(struct message_node), GFP_KERNEL);
    if (node == NULL) {
        printk(KERN_ERR "Could not create the node as a null pointer was returned\n");
        return NULL;
    }
    node->address = address_p;

    //transport structure
    node->transport = transport;
    if (node->transport == NULL) success = false; //this can be caused when the protocol is not in the protocol list

    //handlers
    success = success && setup_handlers(node);

    if (!success) {
        kfree(node);
        printk(KERN_ERR "Failed to create the node");
        return NULL;
    }

    return node;
}

int find_first_null_pointer(void) {
    int i = 0;
    
    //keep going until you find a gap
    while (get_node(i) != NULL) i++;
    
    return i;
}

//disable and disconnect
bool disable_node(int index) {
    struct message_node node = get_node(index);
    return node->protocol_s->destroy_connection(node);
}

//enable and connect
bool enable_node(int index) {
    struct message_node node = get_node(index);
    if (index < _nid) {
        return node->protocol_s->connect_to_server(node);
    }
    else {
        return node->protocol_s->accept_client(node);
    }
}

const char* protocol_to_string(enum protocol_t protocol) {
    if (protocol >= NUMBER_OF_PROTOCOLS || protocol < 0) {
        printk(KERN_ERR "The protocol was invalid");
        return "INVALID";
    }
    return protocol_strings[protocol];
}

struct pcn_kmsg_transport* string_to_transport(char* protocol) {
    struct transport_list* transport = transport_list_head;

    while (transport->next != NULL) {
        if (strcmp(transport->transport_structure->name, protocol) == 0) return transport->transport_structure; //the integers are mapped to enums
        transport = transport->next;
    }

    //exited so must have not found a suitable protocol
    printk(KERN_ERR "The protocol provided did not match any that were loaded %s\n", protocol);
    return NULL;
}

///////////////stub for address translation
uint32_t address_string_to_int(char* address) { //////////////////////////////////remove this function and replace 
    return in_aton(address);
}

void save_to_file(void) {
    /*struct message_node* node;
    FILE *fileptr = fopen(NODE_LIST_FILE_ADDRESS, "w");

    if (fileptr == NULL) {
        printk(KERN_ERR "The node list file could not be opened and so could not be saved");
        return;
    }

    int i;
    for (i = 0; i < after_last_node_index; i++) {
        node = get_node(i);
        if (node != NULL) {
            fMSGPRINTK(fileptr, "%s,%s\n", address_int_to_string(node->address), protocol_to_string(node->protocol));
        }
    }

    fclose(fileptr);*/
    return;
}

struct node_list* create_node_list(void) {
	struct node_list* ret = kmalloc(sizeof(struct node_list), GFP_KERNEL);
	MSGPRINTK("A new node list was added\n");
	return ret;
}

/**
 * Takes a node and adds it to the node list.
 * @param message_node* node the node that will be added to the list
 * @return int index of the location of the new node (-1 if it could not be added)
*/
int add_node(struct message_node* node) { //function for adding a single node to the list
	int index;
	int i;
	int list_number;
	struct node_list* list = root_node_list;
	#ifdef CONFIG_POPCORN_CHECK_SANITY
			if (after_last_node_index != 0) {
				BUG_ON(get_node(after_last_node_index - 1) != NULL); //ensure that the previous node has not been used
			}
	#endif

	//naviagate to the appropriate list
	//List number:       index / MAX_NUM_NODES_PER_LIST
	//Index within list: index % MAX_NUM_NODES_PER_LIST
	index = find_first_null_pointer(); //first free space (may be on a list that needs creating)
	list_number = index / MAX_NUM_NODES_PER_LIST;
	for (i = 0; i < list_number; i++) {
		#ifdef CONFIG_POPCORN_CHECK_SANITY
				BUG_ON(list->next_list == NULL); //a list must have been removed without deleting the pointer or updating the length variable
		#endif
		if (list->next_list == NULL) {
			list->next_list = create_node_list();
			break; //this ensures that a list can only be added once
		}
		list = list->next_list; //move to next list
	}

	//add to that list
	list->nodes[index % MAX_NUM_NODES_PER_LIST] = node;
	if (index > after_last_node_index) after_last_node_index = index + 1; //this is used when looping through list

    node->index = index;

    //initialise communications
    if (!node->transport->is_initialised) {
        if (node->transport->init_transport(node)) MSGPRINTK("Initialised transport for %s (this should only be done once)\n", node->tranport->name);
        else {
            MSGPRINTK("Failed to initialise tranport for %s\n", node->transport->name);
            remove_node(index);
            return -1; //could not be added
        }
    }
    if (!node->transport->init_node(node)) { //start the communication
        MSGPRINTK("Failed to initialise a node on the %s transport\n", node->transport->name);
        remove_node(index);
        return -1;
    }

    node->transport->number_of_users++; //keep a count so that it is known when to unload the transport when no one is using it

	return index;
}

void remove_node(int index) {
    int i;
    int list_number;
    struct node_list* list;
    disable_node(index); //sets to the always fail transport

    node->transport->kill_node(node);

    if (node->transport->number_of_users <= 0) {
        node->transport->exit_transport();
        MSGPRINTK("No nodes are using %s as transport, removing this transport\n", node->transport->name);
    }

    kfree(get_node(index)); //node has been disabled so cannot be used now
    
    //update the last node index
    i = index;
    if (index + 1 == after_last_node_index) {
        while (i > 0 && get_node(i) != NULL) i--; //roll back until you file a node
        after_last_node_index = i + 1;
    }

    list_number = index / MAX_NUM_NODES_PER_LIST;
    for (i = 0; i < list_number; i++) {
	#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(list->next_list == NULL); //a list must have been removed without deleting the pointer or updating the length variable
	#endif
	if (list->next_list == NULL) {
		list->next_list = create_node_list();
		break; //this ensures that a list can only be added once
	}
	list = list->next_list; //move to next list
    }
    
    list->nodes[index % MAX_NUM_NODES_PER_LIST] = NULL;

}

struct message_node* parse_node(char* node_string) {
    int i;
    int j;
    struct message_node* rtn;
    char* address = kmalloc(sizeof(char) * MAX_FILE_LINE_LENGTH, GFP_KERNEL);
    char* protocol = kmalloc(sizeof(char) * MAX_FILE_LINE_LENGTH, GFP_KERNEL);
    //
    //    Structure of CSV line: address, protocol
    //
    i = 0;
    while (i < MAX_FILE_LINE_LENGTH && node_string[i] != '\0' && node_string[i] != ',') i++;
    if (i >= MAX_FILE_LINE_LENGTH) {
        MSGPRINTK("The address was malformed in the node list file\n");
        return NULL;
    }
    else {
        memcpy(address, &node_string[0], i);
        address[i] = '\0'; //finishes the string
    }

    j = i + 1; //move past the comma
    while (j < MAX_FILE_LINE_LENGTH && node_string[j] != '\n' &&node_string[j] != '\0' && node_string[j] != ',') j++;
    if (j >= MAX_FILE_LINE_LENGTH) {
        MSGPRINTK("The protocol was malformed in the node list file\n");
        return NULL;
    }
    else {
        memcpy(protocol, &node_string[i + 1], j - i - 1);
        protocol[j - i] = '\0'; //finishes the string
    }

    rtn = create_node(address_string_to_int(address), string_to_transport(protocol));

    kfree(address);
    kfree(protocol);

    return rtn;
}

bool get_node_list_from_file(const char * address) {
    /*FILE * fileptr = fopen(address, "r");

    if (fileptr == NULL) {
        MSGPRINTK("The node list file could not be opened and so the node list could not be found");
        */return false;/*
    }

    char line[MAX_FILE_LINE_LENGTH];
    struct message_node* new_node;
    while (fgets(line, MAX_FILE_LINE_LENGTH, fileptr)) {
        new_node = parse_node(line);
        if (new_node == NULL) { //process each node line by line
            MSGPRINTK("Failed to parse node line: %s\n", line);

            //should the function revert? Returns false so doesn't try any more after this one

            return false;

        }
        else add_node(new_node);
    }

    fclose(fileptr);

    return true;*/
}


static uint32_t __init __get_host_ip(void)
{
	struct net_device *d;
	for_each_netdev(&init_net, d) {
		struct in_ifaddr *ifaddr;

		for (ifaddr = d->ip_ptr->ifa_list; ifaddr; ifaddr = ifaddr->ifa_next) {
			int i;
			uint32_t addr = ifaddr->ifa_local;
			for (i = 0; i < after_last_node_index; i++) {
				if (get_node(i) != NULL && addr == get_node(i)->address) {
					return addr;
				}
			}
		}
	}
	return -1;
}

bool __init identify_myself(void)
{
	int i;
	uint32_t my_ip;

	my_ip = __get_host_ip();

	for (i = 0; i < after_last_node_index; i++) {
		char *me = " ";
		if (get_node(i) != NULL && my_ip == get_node(i)->address) {
			my_nid = i;
			me = "*";
		}
		PCNPRINTK("%s %d: %d\n", me, i, get_node(i)->address);
	}

    if (after_last_node_index == 0) PCNPRINTK("No nodes in the list to display\n");

	if (my_nid < 0) {
		PCNPRINTK_ERR("My IP is not listed in the node configuration\n");
		//return false; //if the IP is not listed then it should be added
	}

	return true;
}

void initialise_node_list(void) {

    #ifdef POPCORN_SOCK_ON
    init_sock(); //initialises all tcp stuff that needs to be done before the first node is added
    #endif
    #ifdef POPCORN_RDMA_ON
    //init_rdma();
    #endif

    // add more protocols as needed, remember to include them as a header file and they should be of the same form as socket.h
    // also add individual node initialisationns in the add_node, remove_node and destroy_node_list functions



    MSGPRINTK("Initialising existing node list...\n");
    if (!get_node_list_from_file(NODE_LIST_FILE_ADDRESS)) MSGPRINTK("The node list file could not be loaded, empty node list is used instead\n"); //need to retreive from an existing file
    MSGPRINTK("Finished creating node list\n");

    my_nid = identify_myself();
}

void destroy_node_list(void) {
    int i;
    for (i = 0; i < after_last_node_index; i++) {
        if (get_node(i)) remove_node(i); //note this disables, tears down connections and frees up memory, the node list file is only updated when saved
    }

    #ifdef POPCORN_SOCK_ON
    destroy_sock(); //initialises all tcp stuff that needs to be done before the first node is added
    #endif
    #ifdef POPCORN_RDMA_ON
    //destroy_rdma();
    #endif
}
#endif