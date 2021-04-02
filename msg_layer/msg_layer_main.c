/**
 * Calls and sets up the TCP and other protocols to run popcorn
 * without being tied to a particular transfer protocol
 */

//protocols
#define POPCORN_SOCK_ON


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <popcorn/node_list.h>

#include "ring_buffer.h"
#include "node_list_manager.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Messaging layer of the popcorn system");

#ifdef POPCORN_SOCK_ON
#include "socket.h" //initialises all tcp stuff that needs to be done before the first node is added
#endif

/**
 * TODO: Populate help text
 */
#define COMMAND_HELP_TEXT "Placeholder for help text - note it cannot go over the max buffer size"

static struct proc_dir_entry *nodes_controller;

int count_parameters (char buffer[COMMAND_BUFFER_SIZE]) {
    int count;
    int i;

    printk(KERN_DEBUG "Counting number of parameters\n");

    count = 1; //count the first parameter each space is a subsequent one
    i = 0;
    while (i < COMMAND_BUFFER_SIZE && buffer[i] != '\0') {
        //loop to end of string
        if (buffer[i] == ' ') count++;
        i++;
    }
    printk(KERN_DEBUG "Finished count\n");
    return count;
}

void parse_error(int number_of_parameters, char buffer[COMMAND_BUFFER_SIZE]) {
    printk(KERN_ERR "Parse error: %d parameters, string is \"%s\"\n", number_of_parameters, buffer);
    strncpy(output_buffer, "ERROR", COMMAND_BUFFER_SIZE);
}

void show_help(void) {
    strncpy(output_buffer, COMMAND_HELP_TEXT, COMMAND_BUFFER_SIZE);
}

static ssize_t parse_commands(struct file *file, const char __user *usr_buff, size_t length, loff_t *position) {
    char buffer[COMMAND_BUFFER_SIZE];
    int number_of_parameters;
    int index;
    int i;
    int max_number_connections;
    char c;
    char protocol[COMMAND_BUFFER_SIZE];
    char address[COMMAND_BUFFER_SIZE];
    int new_position;
    
    if(*position > 0 || length > COMMAND_BUFFER_SIZE) {
        return -EFAULT;
    }
    if (copy_from_user(buffer, usr_buff, length)) {
        return -EFAULT;
    }
    //the buffer now contains the inputted command

    new_position = strlen(buffer);

    printk(KERN_DEBUG "Trimming user input\n");
    for (i = 0; i < COMMAND_BUFFER_SIZE; i++) {
        c = buffer[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == ':' || c == ' ')) {
            //when it's not a letter, number, ., :, or space
            buffer[i] = '\0'; //cut the string early so that line returns and other things are not considered
            printk(KERN_DEBUG "Position the string was terminiated at: %d", i);
            break;
        }
    }
    buffer[i] = '\0'; //in case of where there is no null character and the buffer is full

    printk(KERN_DEBUG "Input from the user: \"%s\"\n", buffer);

    //handle input
    number_of_parameters = count_parameters(buffer);

    printk(KERN_DEBUG "%d parameters were given\n", number_of_parameters);

    /**
     * Note that the length of the buffer has been checked and there must be a
     * NULL character at the end, this means that sscanf should be safe from 
     * buffer overflows
     */

    switch (number_of_parameters) {
        case 1:
            //if (strncmp("save", buffer, sizeof(COMMAND_BUFFER_SIZE)) == 0) node_save();
            if (strncmp("help", buffer, sizeof(COMMAND_BUFFER_SIZE)) == 0) show_help();
            else if (strncmp("highest", buffer, sizeof(COMMAND_BUFFER_SIZE)) == 0) node_highest_index();
            else parse_error(number_of_parameters, buffer);
            break;
        case 2:
            if (sscanf(buffer, "get %d", &index) == number_of_parameters - 1) node_get(index);
            else if (sscanf(buffer, "activate %s", address) == number_of_parameters - 1) activate_popcorn(address);
            else if (sscanf(buffer, "remove %d", &index) == number_of_parameters - 1) node_remove(index);
            else if (sscanf(buffer, "update %d %s", &index, protocol) == number_of_parameters - 1) node_update_protocol(index, protocol);
            //else if (sscanf(buffer, "load %s", file_address) == number_of_parameters - 1) node_load(file_address);
            else parse_error(number_of_parameters, buffer);
            break;
        case 3:
            printk(KERN_DEBUG "Getting here\n"); //////////////////////////////////for debugging
            //printk(KERN_DEBUG "Getting here %d\n", sscanf(buffer, "add %s %s", &address, &protocol)); //////////////////////////////////for debugging
            parse_error(number_of_parameters, buffer);
            break;
        case 4:
            if (sscanf(buffer, "add %s %s %d", address, protocol, max_number_connections) == number_of_parameters - 1) node_add(address, protocol, max_number_connections);
            else parse_error(number_of_parameters, buffer);
            break;
        default:
            parse_error(number_of_parameters, buffer);
   }

   printk(KERN_DEBUG "Resetting position\n");


    //update position
    *position = new_position;
    return new_position;
}

static ssize_t give_output(struct file *file, const char __user *usr_buff, size_t length, loff_t *position) 
{
	char buffer[COMMAND_BUFFER_SIZE];
	int buffer_size;
    
	if(*position > 0 || length < COMMAND_BUFFER_SIZE) return 0;

	buffer_size = snprintf(buffer, COMMAND_BUFFER_SIZE, "%s", output_buffer);

    strncpy(output_buffer, "", COMMAND_BUFFER_SIZE); //reset the output buffer so the same information cannot be recieved twice
	
	if(copy_to_user(usr_buff, buffer, buffer_size)) return -EFAULT;

	*position = buffer_size;
	return buffer_size;
}

static struct file_operations command_channel = 
{
	.owner = THIS_MODULE,
	.read = give_output,
	.write = parse_commands,
};


void initialise_node_list_controller(void) {
    strncpy(output_buffer, "", COMMAND_BUFFER_SIZE); //ensure that it is initialised to being empty
    nodes_controller = proc_create("popcorn_nodes", 0660, NULL, &command_channel);
    printk(KERN_INFO "Node list controller proc created\n");
}

void destroy_node_list_controller(void) {
    proc_remove(nodes_controller);
    printk(KERN_INFO "Node list controller proc removed\n");
}

static void __exit exit_kmsg(void) {
	printk(KERN_INFO "Exiting Popcorn messaging layer...\n");

    #ifdef POPCORN_SOCK_ON
    //add_protocol(transport_sock); //initialises all tcp stuff that needs to be done before the first node is added
    #endif
    #ifdef POPCORN_RDMA_ON
    //init_rdma();
    #endif

    // add more protocols as needed, they will need to be removed when exitting too, they should be included
    // as a header file implementing the pcn_kmsg_transport as an interface

	printk(KERN_INFO "Popcorn messaging layer: destroying node list controller\n");
	destroy_node_list_controller(); //call first to avoid user changing node list while destroying it

	printk(KERN_INFO "Popcorn messaging layer: removing peers proc\n");
	//proc_remove(proc_entry);

	printk(KERN_INFO "Popcorn messaging layer: destroying node list\n");
    destroy_node_list();


	printk(KERN_INFO "Removing message layer protocols\n");
    #ifdef POPCORN_SOCK_ON
    remove_protocol(&transport_socket); //initialises all tcp stuff that needs to be done before the first node is added
    #endif
    #ifdef POPCORN_RDMA_ON
    destroy_rdma();
    #endif

    //add more protocols as needed

	printk(KERN_INFO "Popcorn messaging layer has been unloaded\n");
}

static int __init init_kmsg(void) {
	printk(KERN_INFO "Loading Popcorn messaging layer...\n");

	printk(KERN_INFO "Popcorn messaging layer: Adding protocols for messaging layer\n");
    #ifdef POPCORN_SOCK_ON
    if (add_protocol(&transport_socket)) goto exit_message_layer; //initialises all tcp stuff that needs to be done before the first node is added
    #endif
    /*#ifdef POPCORN_RDMA_ON
    add_rdma();
    #endif*/

	printk(KERN_INFO "Popcorn messaging layer: initialising node list\n");
	if (!initialise_node_list()) goto exit_message_layer;

	/**
	 * TODO: Remove peers proc - this will be replaced by the popcorn-nodes proc but is useful to
	 * test that they both give same result, defined for socket
	 */
	printk(KERN_INFO "Popcorn messaging layer: initialising peers proc\n");
	//peers_init();
	
	printk(KERN_INFO "Popcorn messaging layer: initialising node list controller\n");
	initialise_node_list_controller(); //allow user to change nodes

    return 0;

	exit_message_layer:
		exit_kmsg();
        return -1;
}

module_init(init_kmsg);
module_exit(exit_kmsg);
