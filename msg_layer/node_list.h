#include <linux/slab.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define LENGTH_OF_IPV4_ADDRESS_STRING 16 //"192.168.192.168\0" is max length
#define MAX_NUMBER_OF_NODES 64
#define NODE_LIST_FILE_ADDRESS "node_list_file.csv" ///////////////////////////////////update this, find appropriate place for this file to be
#define MAX_FILE_LINE_LENGTH 2048

//these are the available protocols
#define NUMBER_OF_PROTOCOLS 2
enum protocol_t {TCP, RDMA}; //update both this and the following line to add more protocols
const char* protocol_strings[NUMBER_OF_PROTOCOLS] = {"TCP", "RDMA"}; //ensure that the strings are in the same order as above line
#define DEFAULT_PROTOCOL TCP

int after_last_node_index;

struct q_item {
	struct pcn_kmsg_message *msg;
	unsigned long flags;
	struct completion *done;
};

struct message_node {
	uint32_t address;
	bool enabled;
	enum protocol_t protocol; //define acceptable protocols
	struct sock_handle *handle;
	struct pcn_kmsg_transport *transport;
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

#define MAX_NUM_NODES_PER_LIST 64 //absolute maximum number of nodes

struct node_list { //////////////////////////////////////not currently being used
	message_node* nodes[MAX_NUM_NODES_PER_LIST];
	message_list* next_list;
};

bool set_transport_structure(struct message_node* node) {
    return true; //////////////////////stub, will need to check protocol in the popcorn module
}

struct message_node *node_list[MAX_NUMBER_OF_NODES] = {0};

struct message_node* get_node(int index) { ///////////////////////////////////////////function will need to be adjusted to whatever it is
    if (index >= MAX_NUMBER_OF_NODES) {
        MSGPRINTK("The index %d is greater than the number of nodes %d (indexed from zero)", index, MAX_NUMBER_OF_NODES);
        return NULL;
    }
    if (node_list[index] == NULL) {
        MSGPRINTK("There is no node at this index, %d, this is likely because the node has been removed or an incorrect index is being used\n", index);
        return NULL;
    }
    return node_list[index];
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

    struct message_node* node = kmalloc(sizeof(struct message_node));
    if (node == NULL) {
        MSGPRINTK("Could not create the node as a null pointer was returned");
        exit(1);
    }
    node->address = address_p;
    node->protocol = protocol_p;
    node->enabled = false; //blocks this node from being used until the node is added to the node list

    success = set_transport_structure(node);

    if (!success) {
        kfree(node);
        MSGPRINTK("Failed to create the node");
        return NULL;
    }

    return node;
}

int find_first_null_pointer() {
    if (after_last_node_index == 0) return 0; //the node list is empty
    int i = 0;
    while (get_node(i) != NULL && i < MAX_NUMBER_OF_NODES) {
        i++;
    }

    if (i >= MAX_NUMBER_OF_NODES) {////////////////////////////////arbitary max
        MSGPRINTK("There were no free spaces in the node_list");
        exit(1);
    }/////////////////////////////////////////////////
    
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
        MSGPRINTK("The protocol was invalid");
        return "INVALID";
    }
    return protocol_strings[protocol];
}

enum protocol_t string_to_protocol(char* protocol) {
    for (int i = 0; i < NUMBER_OF_PROTOCOLS; i++) {
        if (strcmp(protocol_strings[i], protocol) == 0) return i; //the integers are mapped to enums
    }
    MSGPRINTK("The string did not match any of the protocols known. Defaulting to %s\n", protocol_strings[DEFAULT_PROTOCOL]);
    return DEFAULT_PROTOCOL;
}

///////////////stub for address translation
uint32_t address_string_to_int(char* address) { //////////////////////////////////remove this function and replace 
    return in_aton(address);
}
char* address_int_to_string(uint32_t address) { ///////////////////////////////////remove and replace this function
    return inet_ntoa(address);
}
///////////////end of stub for address translation

void save_to_file() {
    FILE *fileptr = fopen(NODE_LIST_FILE_ADDRESS, "w");

    if (fileptr == NULL) {
        MSGPRINTK("The node list file could not be opened and so could not be saved");
        exit(1);
    }

    struct message_node* node;
    for (int i = 0; i < after_last_node_index; i++) {
        node = get_node(i);
        if (node != NULL) {
            fMSGPRINTK(fileptr, "%s,%s\n", address_int_to_string(node->address), protocol_to_string(node->protocol));
        }
    }

    fclose(fileptr);
}

/**
 * Takes a node and adds it to the node list.
 * @param message_node* node the node that will be added to the list
 * @return int index of the location of the new node (-1 if it could not be added)
*/
int add_node(struct message_node *node) {
    int index = find_first_null_pointer();
    if (index == -1) {
        MSGPRINTK("Could not get a space for the node within the note list");
        return -1;
    }
    if (index > MAX_NUMBER_OF_NODES) {
        MSGPRINTK("Max number of nodes exceeded\n");
        return -1; /////////////////////////////////////////////remove arbitary limit
    }

    node_list[index] = node; ///////////////////////////////////////////////////change to be whatever structure it should be

    if (index == after_last_node_index) after_last_node_index++; //increment so that the end is one larger (this is the next free node)

    enable_node(index); //establishes connections

    return index;
}

void remove_node(int index) {
    disable_node(index); //disables and tears down connections
    struct message_node* node = get_node(index); //get so it can be deleted from list so it cannot be accessed before it is freed

    //update the last node index
    int i = index;
    if (index + 1 == after_last_node_index) {
        while (i > 0 && get_node(i) != NULL) i--; //roll back until you file a node
        after_last_node_index = i + 1;
    }

    node_list[index] = NULL; //////////////////////////////////////change according to structure

    kfree(node);
}

struct message_node* parse_node(char* node_string) {
    char* address = kmalloc(sizeof(char) * MAX_FILE_LINE_LENGTH);
    char* protocol = kmalloc(sizeof(char) * MAX_FILE_LINE_LENGTH);
    //
    //    Structure of CSV line: address, protocol
    //
    int i = 0;
    while (i < MAX_FILE_LINE_LENGTH && node_string[i] != '\0' && node_string[i] != ',') i++;
    if (i >= MAX_FILE_LINE_LENGTH) {
        MSGPRINTK("The address was malformed in the node list file\n");
        return NULL;
    }
    else {
        memcpy(address, &node_string[0], i);
        address[i] = '\0'; //finishes the string
    }

    int j = i + 1; //move past the comma
    while (j < MAX_FILE_LINE_LENGTH && node_string[j] != '\n' &&node_string[j] != '\0' && node_string[j] != ',') j++;
    if (j >= MAX_FILE_LINE_LENGTH) {
        MSGPRINTK("The protocol was malformed in the node list file\n");
        return NULL;
    }
    else {
        memcpy(protocol, &node_string[i + 1], j - i - 1);
        protocol[j - i] = '\0'; //finishes the string
    }

    struct message_node* rtn = create_node(address_string_to_int(address), string_to_protocol(protocol));

    kfree(address);
    kfree(protocol);

    return rtn;
}

bool get_node_list_from_file(const char * address) {
    FILE * fileptr = fopen(address, "r");

    if (fileptr == NULL) {
        MSGPRINTK("The node list file could not be opened and so the node list could not be found");
        exit(1);
    }

    char line[MAX_FILE_LINE_LENGTH];
    struct message_node* new_node;
    while (fgets(line, MAX_FILE_LINE_LENGTH, fileptr) != NULL) {
        new_node = parse_node(line);
        if (new_node == NULL) { //process each node line by line
            MSGPRINTK("Failed to parse node line: %s\n", line);

            //should the function revert? Returns false so doesn't try any more after this one

            return false;

        }
        else add_node(new_node);
    }

    fclose(fileptr);

    return true;
}

void initialise_node_list() {
    MSGPRINTK("Initialising existing node list...\n");
    get_node_list_from_file(NODE_LIST_FILE_ADDRESS);
    MSGPRINTK("Finished creating node list\n");
}

void destroy_node_list() {
    for (int i = 0; i < after_last_node_index, i++) {
        if (node_exists(i)) remove_node(i); //note this disables and frees up memory, the node list file is only updated when saved


        //UPDATE ALL THE PRINT STATEMENTS

    }
}