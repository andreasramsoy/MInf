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

#define NODE_LIST_FILE_ADDRESS "/node_list_file.csv" ///////////////////////////////////update this, find appropriate place for this file to be
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
	
    printk(KERN_DEBUG "Getting the node %d\n", index);

    if (list == NULL) {
        printk(KERN_DEBUG "Fetching a list when there is no node lists (this happens when there are no nodes\n");
        return NULL;
    }
	
	//move to the appropriate list
	//List number:       index / MAX_NUM_NODES_PER_LIST
	//Index within list: index % MAX_NUM_NODES_PER_LIST
	list_number = index / MAX_NUM_NODES_PER_LIST;
	for (i = 0; i < list_number; i++) {
        if (list->next_list == NULL) {
            printk(KERN_INFO "The node trying to be fetched does not exist (or even the node list it is supposed to be on)\n");
            return NULL;
        }
		list = list->next_list; //move to next list
	}

    printk(KERN_DEBUG "On correct list, getting node\n");
	
	//should be on correct list now just directly return the node
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
    struct message_node* node;
    bool successful = true;

    if (transport != NULL) {
        printk(KERN_DEBUG "Creating node with address %d and protocol %s\n", address_p, transport->name);
    }
    else {
        printk(KERN_DEBUG "Creating node with address %d but no protocol was given\n", address_p);
    }

    node = kmalloc(sizeof(struct message_node), GFP_KERNEL);
    if (node == NULL) {
        printk(KERN_ERR "Could not create the node as a null pointer was returned\n");
        return NULL;
    }
    node->address = address_p;

    node->connected = false;

    //transport structure
    node->transport = transport;
    if (node->transport == NULL) {
        successful = false; //this can be caused when the protocol is not in the protocol list
        printk(KERN_ERR "The transport protocol cannot be NULL\n");
    }

    if (!successful) {
        kfree(node);
        printk(KERN_ERR "Failed to create the node\n");
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
    printk(KERN_DEBUG "Disabling node %d\n", index);
    if (node == NULL || node->transport == NULL) {
        printk(KERN_DEBUG "Either node is NULL or it does not have transport");
        return false;
    }
    node->connected = !(node->transport->kill_node(node)); //destroys the connection
    return node->connected;
}

//enable and connect
bool enable_node(int index) {
    struct message_node* node;
    printk(KERN_DEBUG "Enabling node %d\n", index);

    node = get_node(index);
    if (node == NULL || node->transport == NULL) {
        printk(KERN_DEBUG "Node cannot be enabled when it is NULL or doesn't have transport");
    }
    node->connected = node->transport->init_node(node); //destroys the connection
    return node->connected;
}

char* protocol_to_string(struct pcn_kmsg_transport* transport) {
    printk(KERN_DEBUG "protocol_to_string called");
    if (transport == NULL) {
        printk(KERN_ERR "The protocol was invalid");
        return "INVALID";
    }
    return transport->name;
}

struct pcn_kmsg_transport* string_to_transport(char* protocol) {
    struct transport_list* transport;

    printk(KERN_DEBUG "string_to_transport called\n");
    transport = transport_list_head;

    if (strcmp(transport->transport_structure->name, protocol) == 0) {
        printk(KERN_DEBUG "string_to_transport called 1.5\n");
        return transport->transport_structure;
    }

    printk(KERN_DEBUG "string_to_transport called 2\n");
    while (transport->next != NULL) {
        printk(KERN_DEBUG "string_to_transport called in loop\n");
        transport = transport->next;
        if (strcmp(transport->transport_structure->name, protocol) == 0) return transport->transport_structure;
    }

    //exited so must have not found a suitable protocol
    printk(KERN_ERR "The protocol provided did not match any that were loaded %s\n", protocol);
    return NULL;
}

uint32_t address_string_to_int(char* address) {
    return in_aton(address);
}

bool save_to_file(void) {
    /*struct message_node* node;
    FILE *fileptr = fopen(NODE_LIST_FILE_ADDRESS, "w");

    if (fileptr == NULL) {
        printk(KERN_ERR "The node list file could not be opened and so could not be saved");
        return false;
    }

    int i;
    for (i = 0; i < after_last_node_index; i++) {
        node = get_node(i);
        if (node) {
            fprintk(KERN_DEBUG fileptr, "%s,%s\n", address_int_to_string(node->address), protocol_to_string(node->transport->name));
        }
    }

    fclose(fileptr);*/
    return true;
}

struct node_list* create_node_list(void) {
    int i;
	struct node_list* new_list = kmalloc(sizeof(struct node_list), GFP_KERNEL);
    if (new_list == NULL) {
        printk(KERN_ERR "Could not create new node list\n");
    }
    else {
	    printk(KERN_DEBUG "A new node list was added\n");
    }
    for (i = 0; i < MAX_NUM_NODES_PER_LIST; i++) {
        new_list->nodes[i] = NULL; //initialise to NULL so that get_node can just return NULL
    }
	return new_list;
}

void remove_node(int index) {
    int i;
    int list_number;
    bool no_nodes;
    struct node_list* prev_list;
    struct node_list* list = root_node_list;
    struct message_node* node = get_node(index);
    disable_node(index); //sets to the always fail transport
    printk(KERN_DEBUG "Node has been disabled\n");

    if (node->transport->is_initialised) {
        printk(KERN_DEBUG "Killing connections for this node\n");
        node->transport->kill_node(node);

        node->transport->number_of_users--;

        printk(KERN_DEBUG "Connections have been killed for this node\n");

        if (node->transport->number_of_users <= 0) {
            node->transport->exit_transport();
            printk(KERN_DEBUG "No nodes are using %s as transport, removing this transport\n", node->transport->name);
        }
    }

    printk(KERN_DEBUG "Updating the after last node index\n");
    
    //update the last node index
    i = index;
    if (index == after_last_node_index || index + 1 == after_last_node_index) {
        while (i > 0 && get_node(i) != NULL) i--; //roll back until you file a node
        after_last_node_index = i + 1;
    }

    printk(KERN_DEBUG "Navigating through list to remove node\n");

    //go to the list that contains it to remove it
    list_number = index / MAX_NUM_NODES_PER_LIST;
    for (i = 0; i < list_number; i++) {
        if (list->next_list == NULL) {
            printk(KERN_ERR "Trying to access next list but it does not exist\n");
        }
        else {
            prev_list = list;
	        list = list->next_list; //move to next list
        }
    }
    printk(KERN_DEBUG "Removing node from list\n");
    list->nodes[index % MAX_NUM_NODES_PER_LIST] = NULL;


    printk(KERN_DEBUG "Removing excess node lists\n");
    no_nodes = true;
    for (i = 0; i < MAX_NUM_NODES_PER_LIST; i++) {
        if (list->nodes[i] != NULL) {
            no_nodes = false;
            break;
        }
    }
    if (no_nodes) {
        printk(KERN_DEBUG "This node list is empty, removing it\n");
        if (prev_list != NULL) {
            //not the first list
            prev_list = list->next_list; //jump over list
        }
        printk(KERN_DEBUG "Removing the item from list\n");
        kfree(list);
    }
}

bool is_myself(struct message_node* node)
{
	struct net_device *d;
    printk(KERN_DEBUG "Checking if this node is myself\n");
    if (!node) {
        printk(KERN_INFO "Cannot check a NULL node");
        return false;
    }
	for_each_netdev(&init_net, d) {
		struct in_ifaddr *ifaddr;

		for (ifaddr = d->ip_ptr->ifa_list; ifaddr; ifaddr = ifaddr->ifa_next) {
			int i;
			uint32_t addr = ifaddr->ifa_local;
			for (i = 0; i < after_last_node_index; i++) {
				if (addr == node->address) {
					return true;
				}
			}
		}
	}
	return false;
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

    if (node == NULL) {
        printk(KERN_ERR "Trying to add a NULL node\n");
        return -1;
    }

    printk(KERN_DEBUG "Adding new node %d\n", node->address);

	//naviagate to the appropriate list
	//List number:       index / MAX_NUM_NODES_PER_LIST
	//Index within list: index % MAX_NUM_NODES_PER_LIST
	index = find_first_null_pointer(); //first free space (may be on a list that needs creating)
    printk(KERN_DEBUG "Searching for position %d\n", index);
	list_number = index / MAX_NUM_NODES_PER_LIST;
	for (i = 0; i < list_number; i++) {
		if (list->next_list == NULL) {
            printk(KERN_DEBUG "End of node list reached - adding new list of nodes\n");
			list->next_list = create_node_list();
            if (list->next_list == NULL) {
                printk(KERN_ERR "Did not create the list, cannot add node\n");
                return -1;
            }
		    list = list->next_list; //move to the new list
			break; //this ensures that a list can only be added once
		}
		list = list->next_list; //move to next list
	}

    if (index == 0) {
        printk(KERN_DEBUG "First item, adding first node list\n");
        root_node_list = create_node_list();
        if (root_node_list == NULL) {
            printk(KERN_ERR "Did not create the list, cannot add node\n");
            return -1;
        }
        list = root_node_list; //need to set this again because it will have been initialised to NULL
    }

	//add to that list
	list->nodes[index % MAX_NUM_NODES_PER_LIST] = node;
	if (index > after_last_node_index) after_last_node_index = index + 1; //this is used when looping through list

    node->index = index;

    if (node->transport == NULL) {
        printk(KERN_ERR "The transport of the node cannot be NULL\n");
        remove_node(index);
        return -1;
    }

    printk(KERN_DEBUG "Initialising communications for node\n");
    printk(KERN_DEBUG "Transport for the node initialised?    %d\n", node->transport->is_initialised);
    printk(KERN_DEBUG "Transport for the node name?    %s\n", node->transport->name);

    if (!is_myself(node)) {
        //initialise communications
        if (!(node->transport->is_initialised)) {
            printk(KERN_DEBUG "This transport has not been initialised before\n");
            if (!(node->transport->init_transport())) printk(KERN_DEBUG "Initialised transport for %s (ensure this is only done once for each protocol)\n", node->transport->name);
            else {
                printk(KERN_DEBUG "Failed to initialise tranport for %s\n", node->transport->name);
                remove_node(index);
                return -1; //could not be added
            }
        }
        printk(KERN_DEBUG "Transport initialised\n");

        if (!enable_node(index)) {
            printk(KERN_ERR "Could not enable node\n");
            remove_node(index);
            return -1;
        }
        printk(KERN_DEBUG "Node enabled\n");

        node->transport->number_of_users++; //keep a count so that it is known when to unload the transport when no one is using it
    }
    else {
        printk(KERN_DEBUG "This node is myself, skipping initialising connection");
    }

    printk(KERN_DEBUG "Successfully added node at index %d\n", index);

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
        printk(KERN_DEBUG "The address was malformed in the node list file\n");
        return NULL;
    }
    else {
        memcpy(address, &node_string[0], i);
        address[i] = '\0'; //finishes the string
    }

    j = i + 1; //move past the comma
    while (j < MAX_FILE_LINE_LENGTH && node_string[j] != '\n' &&node_string[j] != '\0' && node_string[j] != ',') j++;
    if (j >= MAX_FILE_LINE_LENGTH) {
        printk(KERN_DEBUG "The protocol was malformed in the node list file\n");
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
    /*char line[MAX_FILE_LINE_LENGTH];
    struct message_node* new_node;
    struct message_node* node;
    FILE * fileptr;
    int i;

    printk(KERN_DEBUG "Removing previous nodes from node list\n");
    for (i = 0; i < after_last_node_index; i++) {
        node = get_node(i);
        if (node) {
            remove_node(i);
            kfree(node);
        }
    }
    
    fileptr = fopen(address, "r");

    if (fileptr == NULL && strcmp(NODE_LIST_FILE_ADDRESS, address) != 0) {
        printk(KERN_DEBUG "The node list file could not be opened\n");
        printk(KERN_DEBUG "Attempting to revert to previously saved node list\n");
        return get_node_list_from_file(NODE_LIST_FILE_ADDRESS);
    }
    else if (fileptr == NULL) {
        printk(KERN_DEBUG "The default node list file could not be opened\n");
        */return false;/*
    }

    while (fgets(line, MAX_FILE_LINE_LENGTH, fileptr)) {
        new_node = parse_node(line);
        if (new_node == NULL) { //process each node line by line
            printk(KERN_DEBUG "Failed to parse node line: %s\n", line);
        }
        else if (add_node(new_node) >= 0) {
            printk(KERN_INFO "Failed to add the node to the node list\n");
            kfree(new_node);
        }
        else {
            printk(KERN_DEBUG "Successfully added the new node\n");
        }
    }

    fclose(fileptr);

    return true;*/
}

uint32_t __init __get_host_ip(void)
{
	struct net_device *d;
    printk(KERN_DEBUG "Getting host ip\n");
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
    printk(KERN_DEBUG "Identifying this node in node list\n");

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

    if (after_last_node_index == 0) printk(KERN_DEBUG "No nodes in the list to display\n");

	if (my_nid < 0) {
		printk(KERN_ERR "My IP is not listed in the node configuration\n");
		//return false; //if the IP is not listed then it should be added
	}

	return true;
}

int add_protocol(struct pcn_kmsg_transport* transport_item) {
    struct transport_list* trans_list;
    struct transport_list* new_trans_list;
    if (transport_list_head == NULL) {
        //empty list
        printk(KERN_DEBUG "Transport list is empty, updating list head\n");
        transport_list_head = kmalloc(sizeof(struct pcn_kmsg_transport*), GFP_KERNEL);
        if (transport_list_head == NULL) {
            printk(KERN_DEBUG "Could not create new transport list item for list head\n");
            return 1;
        }
        transport_list_head->transport_structure = transport_item;
        transport_list_head->next = NULL;
    }
	else {
        //non-empty list, go to end and append
        printk(KERN_DEBUG "Moving to end of transport list\n");
		trans_list = transport_list_head;
		while (trans_list->next != NULL) {
			trans_list = trans_list->next;
            printk(KERN_DEBUG "Moved to next item in list\n");
		}
        printk(KERN_DEBUG "Adding new item to transport list\n");
		new_trans_list = kmalloc(sizeof(struct transport_list), GFP_KERNEL);
        if (new_trans_list == NULL) {
            printk(KERN_DEBUG "Could not create new transport list item\n");
            return 1;
        }
		trans_list->next = new_trans_list;
		new_trans_list->transport_structure = transport_item;
		new_trans_list->next = NULL;
	}
    transport_item->is_initialised = false; //ensure not initialised at first
    return 0;
}

void remove_protocol(struct pcn_kmsg_transport* transport_item) {
    struct transport_list* trans_list;
    struct transport_list* new_list;

    if (transport_list_head == NULL) {
        printk(KERN_ERR "More protocols were attempted to be removed than there were in the transport list\n");
    }
    else if (transport_list_head->transport_structure == transport_item) {
        if (transport_list_head->next == NULL) {
            printk(KERN_DEBUG "The transport list head was removed\n");
            //only member of list
            kfree(transport_list_head);
            transport_list_head = NULL;
        }
        else {
            printk(KERN_DEBUG "The transport list head was removed and replaced with the next item in the transport list\n");
            //this is the first transport structure but there are others
            transport_list_head->transport_structure = transport_list_head->next->transport_structure;
            trans_list = transport_list_head->next;
            kfree(trans_list);
            transport_list_head = trans_list; //hop over
        }
	}
	else {
        printk(KERN_DEBUG "Traversing transport list to remove item\n");
		trans_list = transport_list_head;
		while (trans_list->next != NULL && trans_list->next->transport_structure != transport_item) {
			trans_list = trans_list->next;
		}
		if (trans_list->next->transport_structure == transport_item) {
            printk(KERN_DEBUG "Removing the transport list item\n");
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
    struct message_node* node;
    for (i = 0; i < after_last_node_index; i++) {
        node = get_node(i);
        if (node != NULL) {
            remove_node(i); //note this disables, tears down connections
            kfree(node); //frees up memory
        }
        //note that the node list file is only updated when saved (so if someone messes up connections they can just not save and then reboot)
    }
}

bool initialise_node_list(void) {
    struct message_node* myself;
    after_last_node_index = 0;

    if (transport_list_head == NULL || transport_list_head->transport_structure == NULL) {
            printk(KERN_ERR "At least one transport structure must be in the transport list for popcorn to work\n");
            destroy_node_list(); //destroy and exit
            return false;
    }
    else {
        printk(KERN_DEBUG "Initialising existing node list...\n");
        // if (!get_node_list_from_file(NODE_LIST_FILE_ADDRESS)) {
        //     printk(KERN_DEBUG "The node list file could not be loaded, this node will be added to an empty list\n"); //need to retreive from an existing file
        //     /**
        //      * TODO: Add getting the host ip
        //      */
        //     myself = create_node(1, transport_list_head->transport_structure); //create a node with own address and the first transport structure as default
        //     //myself = create_node(__get_host_ip(), transport_list_head->transport_structure); //create a node with own address and the first transport structure as default
        //     if (myself == NULL) {
        //         printk(KERN_ERR "Failed to create node for myself, cannot continue\n");
        //         return false;
        //     }
        //     my_nid = 0; //so that the it knows not establish connections with itself
        //     my_nid = add_node(myself);
        //     if (my_nid < 0) {
        //         printk(KERN_ERR "Created node but failed to add to node list, cannot continue\n");
        //         kfree(myself); //couldn't add so remove it
        //         destroy_node_list();
        //         return false;
        //     }
        //     else printk(KERN_DEBUG "Added myself to node list\n");
        // }
        printk(KERN_DEBUG "Finished creating node list\n");

        if (my_nid == -1) {
            my_nid = identify_myself();
        }
    }
    return true;
}
#endif
