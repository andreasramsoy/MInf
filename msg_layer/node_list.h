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


#define NODE_LIST_FILE_ADDRESS "node_list_file.csv" ///////////////////////////////////update this, find appropriate place for this file to be
#define MAX_FILE_LINE_LENGTH 2048
#define MAX_NUM_NODES_PER_LIST 64 //absolute maximum number of nodes

//these are the available protocols
#define NUMBER_OF_PROTOCOLS 2
enum protocol_t {TCP, RDMA}; //update both this and the following line to add more protocols
const char* protocol_strings[NUMBER_OF_PROTOCOLS] = {"TCP", "RDMA"}; //ensure that the strings are in the same order as above line
#define DEFAULT_PROTOCOL TCP

int node_list_length = 0;
struct node_list* root_node_list; //Do not access directly! Use get_node(i) function

int after_last_node_index;

struct q_item {
	struct pcn_kmsg_message *msg;
	unsigned long flags;
	struct completion *done;
};

struct node_list {
	struct message_node* nodes[MAX_NUM_NODES_PER_LIST];
	struct node_list* next_list;
};

/* Per-node handle for socket */
struct sock_handle {
	int nid;

	/* Ring buffer for queueing outbound messages */
	struct q_item *msg_q;
	unsigned long q_head;
	unsigned long q_tail;
	spinlock_t q_lock;
	struct semaphore q_empty;
	struct semaphore q_full;

	struct socket *sock;
	struct task_struct *send_handler;
	struct task_struct *recv_handler;
};

struct message_node {
	uint32_t address;
	bool enabled;
	enum protocol_t protocol; //define acceptable protocols
	struct sock_handle *handle;
	struct pcn_kmsg_transport *transport;
};

bool set_transport_structure(struct message_node* node) {
    return true; //////////////////////stub, will need to check protocol in the popcorn module
}

///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////  Need to add the node_list transport structure to the pcn_kmsg.c
///////////////////////////  So that the transport structure is actually dynamic
///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////


/* function to access the node_list safely, will return 1 if invalid request
   Also allows for changes in data structure (list to avoid limit of 64 nodes) */
struct message_node* get_node(int index) {
	int list_number;
	int i;
	struct node_list* list = root_node_list;
	
	#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(index >= node_list_length); //node doesn't exist
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
 * @return message_node* node pointer to the new node
*/
struct message_node* create_node(uint32_t address_p, enum protocol_t protocol_p) {
    bool success;

    struct message_node* node = kmalloc(sizeof(struct message_node), GFP_KERNEL);
    if (node == NULL) {
        printk(KERN_ERR "Could not create the node as a null pointer was returned");
        return NULL;
    }
    node->address = address_p;
    node->protocol = protocol_p;
    node->enabled = false; //blocks this node from being used until the node is added to the node list

    success = set_transport_structure(node);

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
    get_node(index)->enabled = false;

    //////////////////////////////////////tear down connections

    return true;
}

//enable and connect
bool enable_node(int index) {
    //uses the node list index to ensure that all nodes with connections are stored there and so tracked
    bool success;

    get_node(index)->enabled = false; //probably already set to false but want to block using connection 
    success = true; //connections set this////////////////////////////////////////establish connections here
    if (success) get_node(index)->enabled = true; //allows connections

    return success;
}

const char* protocol_to_string(enum protocol_t protocol) {
    if (protocol >= NUMBER_OF_PROTOCOLS || protocol < 0) {
        printk(KERN_ERR "The protocol was invalid");
        return "INVALID";
    }
    return protocol_strings[protocol];
}

enum protocol_t string_to_protocol(char* protocol) {
    int i = 0;
    for (i = 0; i < NUMBER_OF_PROTOCOLS; i++) {
        if (strcmp(protocol_strings[i], protocol) == 0) return i; //the integers are mapped to enums
    }
    printk(KERN_ERR "The string did not match any of the protocols known. Defaulting to %s\n", protocol_strings[DEFAULT_PROTOCOL]);
    return DEFAULT_PROTOCOL;
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
			if (node_list_length != 0) {
				BUG_ON(get_node(node_list_length - 1) != NULL); //ensure that the previous node has not been used
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
	after_last_node_index = index; //this is used when looping through list
	node_list_length++; //increment here because there are sanity checks that use this variable

	return index;
}

void remove_node(int index) {
    int i;
    int list_number;
    struct node_list* list;
    disable_node(index); //disables and tears down connections

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

    rtn = create_node(address_string_to_int(address), string_to_protocol(protocol));

    kfree(address);
    kfree(protocol);

    return rtn;
}

bool get_node_list_from_file(const char * address) {
    /*FILE * fileptr = fopen(address, "r");

    if (fileptr == NULL) {
        MSGPRINTK("The node list file could not be opened and so the node list could not be found");
        return false;
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

    fclose(fileptr);*/

    return true;
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

	//load_node_list(); //populated the node_list

	my_ip = __get_host_ip();

	for (i = 0; i < after_last_node_index; i++) {
		char *me = " ";
		if (get_node(i) != NULL && my_ip == get_node(i)->address) {
			my_nid = i;
			me = "*";
		}
		PCNPRINTK("%s %d: %d\n", me, i, get_node(i)->address);
	}

	if (my_nid < 0) {
		PCNPRINTK_ERR("My IP is not listed in the node configuration\n");
		return false;
	}

	return true;
}

void initialise_node_list(void) {
    MSGPRINTK("Initialising existing node list...\n");
    get_node_list_from_file(NODE_LIST_FILE_ADDRESS);
    MSGPRINTK("Finished creating node list\n");
}

void destroy_node_list(void) {
    int i;
    for (i = 0; i < after_last_node_index; i++) {
        if (get_node(i)) remove_node(i); //note this disables, tears down connections and frees up memory, the node list file is only updated when saved
    }
}
