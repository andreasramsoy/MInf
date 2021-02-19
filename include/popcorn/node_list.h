#ifndef __POPCORN_NODE_LIST_H__
#define __POPCORN_NODE_LIST_H__


#define POPCORN_SOCK_ON
//#define POPCORN_RDMA_ON

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
#include <popcorn/node_structs.h>
#include <popcorn/pcn_kmsg.h>
#include <popcorn/bundle.h>
#include <popcorn/debug.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>

#define NODE_LIST_FILE_ADDRESS "node_list_file.csv" ///////////////////////////////////update this, find appropriate place for this file to be
#define MAX_FILE_LINE_LENGTH 2048

struct transport_list* transport_list_head;
struct node_list* root_node_list; //Do not access directly! Use get_node(i) function

int after_last_node_index;

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
 * Creates, allocates space and returns a pointer to a node. This function is separate from the add_node, remove_node,
 * etc. so that if the structure of the nodes change then only this function needs to be changed
 * @param uint32_t address the address of new node
 * @param protocol_t protocol the protocol that the new node should use
 * @return message_node* node pointer to the new node, NULL if it could not be created
*/
struct message_node* create_node(uint32_t address_p, struct pcn_kmsg_transport* transport) {
    bool success;

    struct message_node* node = kmalloc(sizeof(struct message_node), GFP_KERNEL);
    if (node == NULL) {
        printk(KERN_ERR "Could not create the node as a null pointer was returned\n");
        return NULL;
    }
    node->address = address_p;

    node->connected = false;

    //transport structure
    node->transport = transport;
    if (node->transport == NULL) {
        success = false; //this can be caused when the protocol is not in the protocol list
        printk(KERN_ERR "The transport protocol cannot be NULL");
    }

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
    struct message_node* node = get_node(index);
    node->connected = !(node->transport->kill_node(node)); //destroys the connection
    return node->connected;
}

//enable and connect
bool enable_node(int index) {
    struct message_node* node = get_node(index);
    node->connected = node->transport->init_node(node); //destroys the connection
    return node->connected;
}

char* protocol_to_string(struct pcn_kmsg_transport* transport) {
    if (transport == NULL) {
        printk(KERN_ERR "The protocol was invalid");
        return "INVALID";
    }
    return transport->name;
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

void remove_node(int index) {
    int i;
    int list_number;
    struct message_node* node = get_node(index);
    struct node_list* list;
    disable_node(index); //sets to the always fail transport

    node->transport->number_of_users--;
    
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

	//naviagate to the appropriate list
	//List number:       index / MAX_NUM_NODES_PER_LIST
	//Index within list: index % MAX_NUM_NODES_PER_LIST
	index = find_first_null_pointer(); //first free space (may be on a list that needs creating)
	list_number = index / MAX_NUM_NODES_PER_LIST;
	for (i = 0; i < list_number; i++) {
		if (list->next_list == NULL) {
			list->next_list = create_node_list();
		    list = list->next_list; //move to the new list
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
        if (node->transport->init_transport()) MSGPRINTK("Initialised transport for %s (ensure this is only done once for each protocol)\n", node->tranport->name);
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
    struct message_node* node;

	my_ip = __get_host_ip();

	for (i = 0; i < after_last_node_index; i++) {
        node = get_node(i);
        if (node != NULL) {
            char *me = " ";
            if (my_ip == node->address) {
                my_nid = i;
                me = "*";
            }
            PCNPRINTK("%s %d: %d\n", me, i, node->address);
        }
	}

    if (after_last_node_index == 0) PCNPRINTK("No nodes in the list to display\n");

	if (my_nid < 0) {
		PCNPRINTK_ERR("My IP is not listed in the node configuration\n");
		//return false; //if the IP is not listed then it should be added
	}

	return true;
}

void add_protocol(struct pcn_kmsg_transport* transport_item) {
    struct transport_list* trans_list;
    struct transport_list* new_trans_list;
    if (transport_list_head->transport_structure == NULL) {
        //empty list
        transport_list_head->transport_structure = transport_item;
    }
	else {
        //non-empty list, go to end and append
		trans_list = transport_list_head;
		while (trans_list->next != NULL) {
			trans_list = trans_list->next;
		}
		new_trans_list = kmalloc(sizeof(struct transport_list), GFP_KERNEL);
		trans_list->next = new_trans_list;
		new_trans_list->transport_structure = transport_item;
		new_trans_list->next = NULL;
	}
}

void remove_protocol(struct pcn_kmsg_transport* transport_item) {
    struct transport_list* trans_list;
    struct transport_list* new_list;
    if (transport_list_head->transport_structure == NULL && transport_list_head->next == NULL) {
        //only member of list
		transport_list_head->transport_structure = NULL;
	}
	else if (transport_list_head->transport_structure == NULL) {
		//this is the first transport structure but there are others
		transport_list_head->transport_structure = transport_list_head->next->transport_structure;
		trans_list = transport_list_head->next;
		transport_list_head->next = trans_list->next; //hop over
		kfree(trans_list);
	}
	else if (transport_list_head->next->structure == transport_item) {
		//edge case of being second in list
        	trans_list = transport_list_head->next->next; //this may be null but doesn't matter
		kfree(transport_list_head->next);
		transport_list_head->next = trans_list;
	}
	else {
		trans_list = transport_list_head;
		while (trans_list->next->next != NULL && trans_list->next->transport_structure != transport_item) {
			trans_list = trans_list->next;
		}
		if (trans_list->next->transport_structure == transport_item) {
			//the next node is the one to be removed
			new_list = trans_list->next;
			trans_list->next = trans_list->next->next; //hop over
			kfree(new_list);
		}
		else {
			printk(KERN_ERR "Failed to remove the %s transport from the transport list, it should be present\n", transport_item->name);
		}
	}
}

void destroy_node_list(void) {
    int i;
    for (i = 0; i < after_last_node_index; i++) {
        if (get_node(i)) remove_node(i); //note this disables, tears down connections and frees up memory, the node list file is only updated when saved
    }
}

bool initialise_node_list(void) {
    struct message_node* myself;
    after_last_node_index = 0;

    if (transport_list_head->transport_structure == NULL) {
            printk(KERN_ERR "At least one transport structure must be in the transport list for popcorn to work\n");
            destroy_node_list(); //destroy and exit
            return false;
    }
    else {
        MSGPRINTK("Initialising existing node list...\n");
        if (!get_node_list_from_file(NODE_LIST_FILE_ADDRESS)) {
            MSGPRINTK("The node list file could not be loaded, this node will be added to an empty list\n"); //need to retreive from an existing file
            myself = create_node(__get_host_ip(), transport_list_head->transport_structure); //create a node with own address and the first transport structure as default
            if (!add_node(myself)) {
                destroy_node_list();
                return false;
            }
        }
        MSGPRINTK("Finished creating node list\n");

        my_nid = identify_myself();
    }
    return true;
}
#endif
