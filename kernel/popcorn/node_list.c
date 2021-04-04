#include <linux/semaphore.h>

#include <popcorn/bundle.h>
#include <popcorn/node_list.h>

#include <popcorn/bundle.h>
#include <popcorn/pcn_kmsg.h>

#include <popcorn/kmesg_types.h>

struct transport_list* transport_list_head;
struct node_list* root_node_list; //Do not access directly! Use get_node(i) function
struct node_list_info_list_item* root_node_list_info_list;
int after_last_node_index;
int number_of_nodes_to_be_added;
char joining_token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES];


#define COMMAND_QUEUE_LENGTH 5 //number of items that can be stored before sending a message to sender
int command_queue_start;
int command_queue_end;

node_list_command* command_queue[COMMAND_QUEUE_LENGTH];

DEFINE_SEMAPHORE(command_queue_sem); //binary semaphore
DEFINE_SEMAPHORE(node_list_info_sem); //binary semaphore

bool registered_on_popcorn_network;

EXPORT_SYMBOL(transport_list_head);
EXPORT_SYMBOL(root_node_list);
EXPORT_SYMBOL(after_last_node_index);
EXPORT_SYMBOL(number_of_nodes_to_be_added);
EXPORT_SYMBOL(joining_token);
EXPORT_SYMBOL(registered_on_popcorn_network);
EXPORT_SYMBOL(root_node_list_info_list);
EXPORT_SYMBOL(node_list_info_sem);



/* function to access the node_list safely, will return 1 if invalid request
   Also allows for changes in data structure (list to avoid limit of 64 nodes) */
struct message_node* get_node(int index) {
	int list_number;
	int i;
	struct node_list* list = root_node_list;
	
    printk(KERN_DEBUG "Getting the node %d\n", index);

    if (list == NULL) {
        //printk(KERN_DEBUG "Fetching a list when there is no node lists (this happens when there are no nodes\n");
        return NULL;
    }
	
	//move to the appropriate list
	//List number:       index / MAX_NUM_NODES_PER_LIST
	//Index within list: index % MAX_NUM_NODES_PER_LIST
	list_number = index / MAX_NUM_NODES_PER_LIST;
	for (i = 0; i < list_number; i++) {
        if (list->next_list == NULL) {
            //printk(KERN_INFO "The node trying to be fetched does not exist (or even the node list it is supposed to be on)\n");
            return NULL;
        }
		list = list->next_list; //move to next list
	}

    //printk(KERN_DEBUG "On correct list, getting node\n");
	
	//should be on correct list now just directly return the node
	return list->nodes[index % MAX_NUM_NODES_PER_LIST];
}
EXPORT_SYMBOL(get_node);

/**
 * Generates the key and IV for AES for the given node. Nothing is returned since 
 * only one thing can be returned at a time
 * @param int index of node that shall get new encryption keys
 */
void generate_symmetric_key(int index) {
    struct message_node* node = get_node(index);
    if (node) {
        #ifdef POPCORN_ENCRYPTION_ON
        printk(KERN_DEBUG "Randomly generating key and IV for node %d\n", index);
        get_random_bytes(node->iv, sizeof(node->iv));
        get_random_bytes(node->key, sizeof(node->key));
        printk(KERN_DEBUG "Done key generation for node %d", index);
        #endif
    }
    else {
        printk(KERN_ERR "Cannot generate symmetric keys for node %d as it does not exist\n", index);
    }
}

/**
 * Creates a node, listens for a connection and accepts any that connect,
 * verify token is correct, delete if it's not
 * @param transport that the node shall listen on and accept connections on
 * @return node with connection (and details filled in) or NULL
 */
struct message_node* create_any_node(struct pcn_kmsg_transport* transport) {
    struct message_node* node;
    bool success;

    printk(KERN_DEBUG "create_any_node called\n");

    node = kmalloc(sizeof(struct message_node), GFP_KERNEL);
    if (!node) {
        success = false;
        printk(KERN_ERR "Could not create the node\n");
        goto create_any_node_failure;
    }

    //previously in bundle.c
    node->is_connected = false;
    node->arch = POPCORN_ARCH_UNKNOWN;
    node->bundle_id = -1;

    node->transport = transport; //set the transport for enable node

    success = enable_node(node);

create_any_node_failure:
    if (success) {
        return node;
    }
    else {
        printk(KERN_ERR "Error while trying to create_any_node\n");
        if (node) kfree(node);
        return NULL;
    }
}
EXPORT_SYMBOL(create_any_node);

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

    //previously in bundle.c
    node->is_connected = false;
    node->arch = POPCORN_ARCH_UNKNOWN;
    node->bundle_id = -1;

    //transport structure
    node->transport = transport;
    if (node->transport == NULL) {
        successful = false; //this can be caused when the protocol is not in the protocol list
        printk(KERN_ERR "The transport protocol cannot be NULL\n");
        goto create_node_end;
    }

    //setup comms
    if (!enable_node(node)) {
        successful = false;
        printk(KERN_ERR "Failed to enable node\n");
    }

create_node_end:
    if (!successful) {
        kfree(node);
        printk(KERN_ERR "Failed to create the node\n");
        return NULL;
    }

    return node;
}
EXPORT_SYMBOL(create_node);


struct message_node* create_instigator_node(uint32_t address_p) {
    struct message_node* node;
    bool successful = true;

    node = kmalloc(sizeof(struct message_node), GFP_KERNEL);
    if (node == NULL) {
        printk(KERN_ERR "Could not create the node as a null pointer was returned\n");
        return NULL;
    }
    node->address = address_p;

    //previously in bundle.c
    node->is_connected = false;
    node->arch = POPCORN_ARCH_UNKNOWN;
    node->bundle_id = -1;

create_node_end:
    if (!successful) {
        kfree(node);
        printk(KERN_ERR "Failed to create the node\n");
        return NULL;
    }

    return node;
}
EXPORT_SYMBOL(create_instigator_node);


int find_first_null_pointer(void) {
    printk(KERN_DEBUG "Find first null pointer called\n");
    int i = 0;
    
    //keep going until you find a gap
    while (get_node(i) != NULL) i++;
    
    return i;
}
EXPORT_SYMBOL(find_first_null_pointer);

//disable and disconnect
bool disable_node(int index) {
    struct message_node* node = get_node(index);
    printk(KERN_DEBUG "Disabling node %d\n", index);
    if (node == NULL || node->transport == NULL) {
        printk(KERN_DEBUG "Either node is NULL or it does not have transport");
        return false;
    }
    return !(node->transport->kill_node(node)); //destroys the connection

#ifdef POPCORN_ENCRYPTION_ON
    //end encryption
	crypto_free_skcipher(node->transform_obj);
    skcipher_request_free(node->cipher_request);
#endif
}
EXPORT_SYMBOL(disable_node);

//enable and connect
bool enable_node(struct message_node* node) {
    printk(KERN_DEBUG "Initialising communications for node\n");
    printk(KERN_DEBUG "Transport for the node initialised?    %d\n", node->transport->is_initialised);
    printk(KERN_DEBUG "Transport for the node name?    %s\n", node->transport->name);

    if (node == NULL || node->transport == NULL) {
        printk(KERN_DEBUG "Node cannot be enabled when it is NULL or doesn't have transport");
        return false;
    }

    //setup connections if first user of a transport structure
    printk(KERN_DEBUG "This node is not myself, initialising connection...\n");
    //initialise communications
    if (!(node->transport->is_initialised)) {
        printk(KERN_DEBUG "This transport has not been initialised before\n");
        if (!(node->transport->init_transport())) printk(KERN_DEBUG "Initialised transport for %s (ensure this is only done once for each protocol)\n", node->transport->name);
        else {
            printk(KERN_DEBUG "Failed to initialise tranport for %s\n", node->transport->name);
            return false;
        }
    }
    printk(KERN_DEBUG "Transport initialised\n");

    node->transport->number_of_users++; //keep a count so that it is known when to unload the transport when no one is using it

#ifdef POPCORN_ENCRYPTION_ON
	//encryption setup
    node->cipher_request = NULL;
    node->transform_obj = NULL;

	//create transform object
	node->transform_obj = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(node->transform_obj)) {
		pr_err("Could not create transform object for AES: %ld\n", PTR_ERR(node->transform_obj));
		goto encryption_fail;
	}

	//set the key according to the node that it was from
	error = crypto_skcipher_setkey(node->transform_obj, node->key, sizeof(node->key));
	if (error) {
		pr_err("Could not set the key for AES error: %d\n", error);
		goto encryption_fail;
	}

	//allocate cipher request
	node->cipher_request = skcipher_request_alloc(node->transform_obj, GFP_KERNEL);
	if (!(node->cipher_request)) {
			printk(KERN_ERR "Could not allocate cipher request\n");
			goto encryption_fail;
	}
#endif

    return node->transport->init_node(node); //destroys the connection
}
EXPORT_SYMBOL(enable_node);

char* protocol_to_string(struct pcn_kmsg_transport* transport) {
    printk(KERN_DEBUG "protocol_to_string called");
    if (transport == NULL) {
        printk(KERN_ERR "The protocol was invalid");
        return "INVALID";
    }
    return transport->name;
}
EXPORT_SYMBOL(protocol_to_string);

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
EXPORT_SYMBOL(string_to_transport);

uint32_t address_string_to_int(char* address) {
    return in_aton(address);
}
EXPORT_SYMBOL(address_string_to_int);

struct node_list* create_node_list(void) {
    int i;
	struct node_list* new_list = kmalloc(sizeof(struct node_list), GFP_KERNEL);
    printk(KERN_DEBUG "create_node_list called\n");

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

bool is_myself(struct message_node* node)
{
	struct net_device *d;
    uint32_t addr;
    struct in_ifaddr *ifaddr;

    printk(KERN_DEBUG "Checking if this node is myself\n");
    if (!node) {
        printk(KERN_INFO "Cannot check a NULL node\n");
    }
	for_each_netdev(&init_net, d) {
        printk(KERN_DEBUG "Checking if this node is myself 2\n");

		for (ifaddr = d->ip_ptr->ifa_list; ifaddr; ifaddr = ifaddr->ifa_next) {
            printk(KERN_DEBUG "Checking if this node is myself 3\n");
            if (!addr) printk(KERN_DEBUG "This is NULL but it should have been checked\n");
			addr = ifaddr->ifa_local;
            printk(KERN_DEBUG "Checking if this node is myself 4\n");
            printk(KERN_DEBUG "My address is: %d.%d.%d.%d\n", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
            if (addr == node->address) {
                my_nid = node->index;
                return true;
            }
		}
	}
	return false;
}
EXPORT_SYMBOL(is_myself);

void remove_node(int index) {
    int i;
    int list_number;
    bool no_nodes;
    struct node_list* prev_list;
    struct node_list* list = root_node_list;
    struct message_node* node = get_node(index);
    disable_node(index); //sets to the always fail transport
    printk(KERN_DEBUG "Node has been disabled\n");

    set_popcorn_node_online(node->index, false);

    if (!is_myself(node)) {
        printk(KERN_DEBUG "Killing connections for this node\n");
        node->transport->kill_node(node);

        node->transport->number_of_users--;

        printk(KERN_DEBUG "Connections have been killed for this node\n");

        if (node->transport->number_of_users <= 0) {
            node->transport->exit_transport();
            printk(KERN_DEBUG "No nodes are using %s as transport, removing this transport\n", node->transport->name);
        }
    }
    else {
        registered_on_popcorn_network = false;
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
EXPORT_SYMBOL(remove_node);

/**
 * Pushes command to the queue
 * @param node_list_command command
 * @return bool success
 */
bool command_queue_push(node_list_command* command) {
    bool success = true;
    int ret;
    do {
        ret = down_interruptible(&command_queue_sem);
    } while (ret);
    

    if ((command_queue_end + 1) % COMMAND_QUEUE_LENGTH == command_queue_start) {
        //if the queue is full
        success = false;
    }
    else {
        //must be space
        command_queue_end = (command_queue_end + 1) % COMMAND_QUEUE_LENGTH;
        command_queue[command_queue_end] = command;
        success = true;
    }

    up(&command_queue_sem);

    return success;
}

/**
 * Function to handle the commands sent to the node list
 */
void process_command(node_list_command* command) {
    struct message_node* node;
    if (command->node_command_type == NODE_LIST_ADD_NODE_COMMAND) {
        printk(KERN_DEBUG "Recieved message from node %d to add a new node!\n", command->sender);
        node = create_node(command->address, string_to_transport(command->transport));
        if (node) {
            if (add_node(node, command->max_connections, command->token) >= 0) printk(KERN_DEBUG "Added the new node\n");
            else {
                printk(KERN_ERR "Failed to add the node! If other nodes succeed then the node list will become inconsistent\n");
                kfree(node);
            }
        }
        else {
            printk(KERN_ERR "Failed to create the node! If other nodes succeed then the node list will become inconsistent\n");
            kfree(node);
        }
    }
    else if (command->node_command_type == NODE_LIST_REMOVE_NODE_COMMAND) {
        printk(KERN_DEBUG "Recieved message from node %d to remove node %d!\n", command->sender, command->nid_to_remove);
        if (my_nid == command->nid_to_remove) {
            /** TODO: Ensure no running processes are remote at this point - this node can start this process */
            printk(KERN_DEBUG "No need to do anything to remove myself - wait for other nodes to end connection\n");
        }
        else {
            printk(KERN_DEBUG "Removing node %d from the node list\n", command->nid_to_remove);
            /** TODO: Ensure no running processes are remote at this point */
            remove_node(command->nid_to_remove);
        }
    }
    else {
        printk(KERN_ERR "A message was sent to the node list but it had an unknown type!\n");
        /** TODO: Should an error message be sent to the node above? */
    }
}

/**
 * Function that processes all items in the queue until it is empty
 */
void command_queue_process(void) {
    node_list_command* command_to_be_processed;
    int ret;
	do {
		ret = down_interruptible(&command_queue_sem);
	} while (ret);
    while (command_queue_start != command_queue_end) {
        command_to_be_processed = command_queue[command_queue_start];
        command_queue_start = (command_queue_start + 1) % COMMAND_QUEUE_LENGTH;
        up(&command_queue_sem);


        //not critical section
        process_command(command_to_be_processed);
        //end of non-criticial section

        do {
            ret = down_interruptible(&command_queue_sem);
        } while (ret);
    } /** TODO: quite ugly error prone code, find a better way of doing this */
    up(&command_queue_sem); //finally release when there are no more commands to process
}

/**
 * Function to handle incoming messages to adjust node list from other nodes
 * @param struct pcn_kmsg_message
 */
static int handle_node_list_command(struct pcn_kmsg_message *msg) {
    node_list_command *command = (node_list_command *)msg;

    printk(KERN_DEBUG "Recieved a command message. Queuing for processing\n");

    command_queue_push(command); //add to the queue

    command_queue_process(); //process all of the commands (does nothing if none are left)

	//smp_mb(); //this function appears in bundle.c, don't think is necessary

	pcn_kmsg_done(msg);
    return 0;
}
EXPORT_SYMBOL(handle_node_list_command);

/**
 * Function to send message to a given node
 * @param int node that messages will be forwarded to children of
 * @param node_list_command_type node_command_type
 * @param uint32_t address
 * @param char* transport_type
 * @param int max_connections
 */
void send_node_command_message(int index, enum node_list_command_type command_type, uint32_t address, char* transport_type, int max_connections) {

	node_list_command command = {
		.sender = my_nid,
		.node_command_type = command_type,
        .address = address,
        .transport = transport_type,
        .max_connections = max_connections,
	};
	pcn_kmsg_send(PCN_KMSG_TYPE_NODE_COMMAND, index, &command, sizeof(command));
}
EXPORT_SYMBOL(send_node_command_message);

/**
 * Function to pass message onto children of node
 * @param int node that messages will be forwarded to children of
 * @param node_list_command_type node_command_type
 * @param uint32_t address
 * @param char* transport_type
 * @param int max_connections
 */
void send_to_child(int node_index, enum node_list_command_type node_command_type, uint32_t address, char* transport_type, int max_connections, char* token) {
    //struct message_node* existing_node; //note the name of one of the parameters is already node
    struct message_node* node;
    int index;
    int i;
    printk(KERN_DEBUG "send_to_child called\n");

    //send to children of binary tree where:
    //  left = 2n
    // right = 2n + 1
    //
    // where a node is missing then this node must send messages to children
    // means that if sucessive nodes are missing then messages increase exponentially
    // this is unlikely though as the first gap will be filled when a node is added

    for (i = 0; i < 2; i++) { //two branches
        index = 2 * (node_index + 1) + i; //note that nid starts at 0, binary trees index from 1 (add one to correct this, take away later)
        node = get_node(index -1);
        if (node) {
            if (node_command_type != NODE_LIST_ADD_NODE_COMMAND || index - 1 != node->index) {
                send_node_command_message(index - 1, node_command_type, address, transport_type, max_connections);
            }
            else {
                printk(KERN_DEBUG "The message was not forwarded to node %lld, as this is the node to be added\n", node->index);
            }
        }
        else if (index - 1 < after_last_node_index) {
            //the node doesn't exist so send to it's would-be children
            send_to_child(index - 1, node_command_type, address, transport_type, max_connections, token);
        }
        else {
            printk(KERN_INFO "No more nodes to propagate to\n");
        }

        /** TODO: Implement waiting for max connections */
        // wait here if the first branch takes up all the connections (max_connections)
    }
}
EXPORT_SYMBOL(send_to_child);

/**
 * Function to send commands to change the node list to other nodes
 * @param node_list_command_type node_command_type
 * @param uint32_t address
 * @param char* transport_type
 * @param int max_connections
 */
void propagate_command(enum node_list_command_type node_command_type, uint32_t address, char* transport_type, int max_connections, char* token) {
    printk(KERN_DEBUG "propagate_command called\n");
    if (my_nid < 0) {
        printk(KERN_ERR "Cannot propagate when this node's my_nid is not set (this happens when we are not a part of any node list)\n");
    }
    else {
        //forward to children
        send_to_child(my_nid, node_command_type, address, transport_type, max_connections, token);
    }
}

/**
 * Adds node at a particular position. This is for when a node has connected
 * to this one which the token and nid and just needs to be placd into the 
 * correct position in the node list.
 * @param node to be added
 * @param position in node list where it shall be placed
 * @return success
 */
bool add_node_at_position(struct message_node* node, int index) {
    int i;
	int list_number;
	struct node_list* list = root_node_list;

    printk(KERN_DEBUG "add_node_at_position called\n");

    if (get_node(index) != NULL) {
        printk(KERN_ERR "Cannot add a node to position %d as a node is already here!", index);
        return false;
    }

    if (root_node_list == NULL) {
        printk(KERN_DEBUG "Adding first node list\n");
        root_node_list = create_node_list();
        if (root_node_list == NULL) {
            printk(KERN_ERR "Did not create the list, cannot add node\n");
            return false;
        }
        list = root_node_list; //need to set this again because it will have been initialised to NULL
    }

    printk(KERN_DEBUG "Searching for correct list to put node into (position %d)\n", index);
	list_number = index / MAX_NUM_NODES_PER_LIST;
	for (i = 0; i < list_number; i++) {
		if (list->next_list == NULL) {
            printk(KERN_DEBUG "End of node list reached - adding new list of nodes\n");
			list->next_list = create_node_list();
            if (list->next_list == NULL) {
                printk(KERN_ERR "Did not create the list, cannot add node\n");
                return false;
            }
		    list = list->next_list; //move to the new list
			break; //this ensures that a list can only be added once
		}
		list = list->next_list; //move to next list
	}

    printk(KERN_DEBUG "Should be on correct list, now add to array\n");

	//add to that list
	list->nodes[index % MAX_NUM_NODES_PER_LIST] = node;

    printk(KERN_DEBUG "Updating the after_last_node_index\n");
	if (index > after_last_node_index) after_last_node_index = index + 1; //this is used when looping through list

    printk(KERN_DEBUG "Setting the index of the node\n");
    node->index = index;

    printk(KERN_DEBUG "Index: %d\n", node->index);
    printk(KERN_DEBUG "Address: %4pI\n", node->address);
    printk(KERN_DEBUG "Handle: %p\n", node->handle);
    printk(KERN_DEBUG "Transport: %4pI\n", node->transport);
    printk(KERN_DEBUG "Arch: %d\n", node->arch);

    if (my_nid != -1 && my_nid != node->index) broadcast_my_node_info_to_node(node->index); //give them info about architecture (done to every node that it connects to)
    set_popcorn_node_online(node->index, true);

    return true;
}
EXPORT_SYMBOL(add_node_at_position);

/**
 * Takes a node and adds it to the node list.
 * @param message_node* node the node that will be added to the list
 * @return int index of the location of the new node (-1 if it could not be added)
*/
int add_node(struct message_node* node, int max_connections, char* token) { //function for adding a single node to the list

    if (node == NULL) {
        printk(KERN_ERR "Trying to add a NULL node\n");
        return -1;
    }

    printk(KERN_DEBUG "Adding new node %4pI\n", node->address);

	//naviagate to the appropriate list
	//List number:       index / MAX_NUM_NODES_PER_LIST
	//Index within list: index % MAX_NUM_NODES_PER_LIST
	if (!add_node_at_position(node, find_first_null_pointer())) { //first free space (may be on a list that needs creating)
        printk(KERN_DEBUG "Could not add the node\n");
        return -1;
    }
    
    if (my_nid != node->index) send_node_list_info(node->index, token); //verfies to the node that you are from the popcorn network

    printk(KERN_DEBUG "Successfully added node at index %lld\n", node->index);

    if (node->index != my_nid) {
        printk(KERN_DEBUG "Propagate command to other nodes\n");
        propagate_command(NODE_LIST_ADD_NODE_COMMAND, node->address, node->transport->name, max_connections, token); //one max connection (replace later)
        printk(KERN_DEBUG "Sent messages to other nodes\n");
    }
    else {
        printk(KERN_DEBUG "Did not propagate this node as it is myself\n");
    }

	return node->index;
}
EXPORT_SYMBOL(add_node);

/**
 * Function to forward details about the node list to an
 * incomming node
 */
void send_node_list_info(int their_index, char random_token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES]) {
    int i;
    int node_count = 0;
    struct message_node* node;
    uint32_t their_address;

    printk(KERN_DEBUG "send_node_list_info called\n");
    
    node = get_node(their_index);
    if (node) {
        their_index = node->address;
    }
    else {
        printk(KERN_ERR "Could not get the node address to send to the node\n");
    }

    node = get_node(my_nid);

    for (i = 0; i < after_last_node_index; i++) {
        if (get_node(i)) {
            node_count++;
        }
    }

    node_count--; //take one away as you've just added the new node (but it does not consider itself a part of the list yet)


    node_list_info node_list_details = {
        .your_nid = their_index,
        .my_nid = my_nid,
        .your_address = their_address,
        .my_address = (node != NULL) ? node->address : 0,
        .number_of_nodes = node_count,
        .token = random_token,
    };
	pcn_kmsg_send(PCN_KMSG_TYPE_NODE_LIST_INFO, their_index, &node_list_details, sizeof(node_list_info));
}
EXPORT_SYMBOL(send_node_list_info);

/**
 * Function to handle incoming messages to adjust node list from other nodes
 * @param struct pcn_kmsg_message
 */
static int handle_node_list_info(struct pcn_kmsg_message *msg) {
    struct node_list_info_list_item* new_info;
    struct node_list_info_list_item* node_list_info_list;
    int ret;

    printk(KERN_DEBUG "Recieved info about the node list\n");
    node_list_info *info = (node_list_info *)msg;

    printk(KERN_DEBUG "Recieved info about the node list 2\n");

	do {
		ret = down_interruptible(&node_list_info_sem);
	} while (ret);

    if (strncmp(joining_token, "", NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES) == 0 && msg->header.from_nid == find_first_null_pointer()) { //the instigator must be the first node in the list
        //this is the instigator node (no other connections made so must be)
        printk(KERN_DEBUG "Has not been set and this is the instigator node\n");
        my_nid = info->your_nid;
        number_of_nodes_to_be_added = info->number_of_nodes;
        strncpy(joining_token, info->token, NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES);
    }

    printk(KERN_DEBUG "Message is from: %d\n", info->my_nid);
    printk(KERN_DEBUG "States that number of nodes in list is: %d\n", info->number_of_nodes);

    printk(KERN_DEBUG "Navigating to end of node info list (root is %p)\n", root_node_list_info_list);
    if (root_node_list_info_list != NULL) {
        printk(KERN_DEBUG "Navigating to end of node info list 2\n");
        node_list_info_list = root_node_list_info_list;
        printk(KERN_DEBUG "Navigating to end of node info list 3\n");
        while (node_list_info_list->next != NULL) {
            printk(KERN_DEBUG "Looping\n");
            printk(KERN_DEBUG "Next pointer is %p\n", node_list_info_list->next);
            node_list_info_list = node_list_info_list->next;
        }
    }

    printk(KERN_DEBUG "Now appending more info to the node info list\n");
    new_info = kmalloc(sizeof(struct node_list_info_list_item), GFP_KERNEL);
    if (new_info == NULL) {
        printk(KERN_ERR "Could not allocate memory for node list info list\n");
	    pcn_kmsg_done(msg);
        return -ENOMEM;
    }

    printk(KERN_DEBUG "Copying info into newly allocated memory\n");
    memcpy(&(new_info->info), info, sizeof(*info)); //copy as the message will be deleted later

    printk(KERN_DEBUG "Placing new info into info list\n");
    new_info->next = NULL;
    if (root_node_list_info_list == NULL) {
        root_node_list_info_list = new_info;
    }
    else {
        node_list_info_list->next = new_info;
    }
    printk(KERN_DEBUG "Done handling new node info\n");
    //now added to the list so that node can be found

	pcn_kmsg_done(msg);
    up(&node_list_info_sem);

    return 0;
}
EXPORT_SYMBOL(handle_node_list_info);

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

/*bool __init identify_myself(void)
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
	}*/

 /*   if (after_last_node_index == 0) printk(KERN_DEBUG "No nodes in the list to display\n");

	if (my_nid < 0) {
		printk(KERN_ERR "My IP is not listed in the node configuration\n");
		//return false; //if the IP is not listed then it should be added
	}

	return true;
}*/

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
EXPORT_SYMBOL(add_protocol);

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
EXPORT_SYMBOL(remove_protocol);

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
EXPORT_SYMBOL(destroy_node_list);

bool initialise_node_list(void) {
    registered_on_popcorn_network = false; //initially not part of any network
    after_last_node_index = 0;
    my_nid = -1;
    number_of_nodes_to_be_added = 0;
    root_node_list_info_list = NULL;

    command_queue_start = 0; //set up queue
    command_queue_end = 0;

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

        /*if (my_nid == -1) {
            my_nid = identify_myself();
        }*/
    }

    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_NODE_COMMAND, node_list_command);
    REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_NODE_LIST_INFO, node_list_info);

    return true;
}
EXPORT_SYMBOL(initialise_node_list);
