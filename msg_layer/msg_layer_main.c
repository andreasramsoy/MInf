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

static struct proc_dir_entry *nodes_controller;

int count_parameters (char buffer[COMMAND_BUFFER_SIZE]) {
    int count = 1; //count the first parameter each space is a subsequent one
    int i = 0;
    while (i < COMMAND_BUFFER_SIZE && buffer[i] != '\0') {
        //loop to end of string
        if (buffer[i] == ' ') count++;
    }
    return count;
}

void parse_error(int number_of_parameters, char buffer[COMMAND_BUFFER_SIZE]) {
    printk(KERN_ERR "Popcorn node command parse error: %d paramets, string is \"%s\"\n", number_of_parameters, buffer);
    strcpy(output_buffer, "ERROR");
}

static ssize_t parse_commands(struct file *file, const char __user *usr_buff, size_t length, loff_t *position) {
    char buffer[COMMAND_BUFFER_SIZE];
    int number_of_parameters;
    int index;
    char* protocol;
    char* file_address;
    char* address;
    int new_position;
    
    if(*position > 0 || length > COMMAND_BUFFER_SIZE) {
        return -EFAULT;
    }
    if (copy_from_user(buffer, usr_buff, length)) {
        return -EFAULT;
    }
    //the buffer now contains the inputted command

    //handle input
    number_of_parameters = count_parameters(buffer);

    switch (number_of_parameters) {
        case 1:
            if (strcmp("save", buffer) == 0) node_save();
            else if (strcmp("highest", buffer) == 0) node_highest_index();
            else parse_error(number_of_parameters, buffer);
            break;
        case 2:
            if (sscanf(buffer, "get %d", &index) == number_of_parameters) get_node(index);
            else if (sscanf(buffer, "remove %d", &index) == number_of_parameters) node_remove(index);
            else if (sscanf(buffer, "update %d %s", &index, protocol) == number_of_parameters) node_update_protocol(index, protocol);
            else if (sscanf(buffer, "load %s", file_address) == number_of_parameters) node_load(file_address);
            else parse_error(number_of_parameters, buffer);
            break;
        case 3:
            if (sscanf(buffer, "add %s %s", address, protocol) == number_of_parameters) node_add(address, protocol);
            else parse_error(number_of_parameters, buffer);
            break;
        default:
            parse_error(number_of_parameters, buffer);
   }


    //update position
    new_position = strlen(buffer);
    *position = new_position;
    return new_position;
}

static ssize_t give_output(struct file *file, const char __user *usr_buff, size_t length, loff_t *position) 
{
	char buffer[COMMAND_BUFFER_SIZE];
	int buffer_size;
    
	if(*position > 0 || length < COMMAND_BUFFER_SIZE) return 0;

	buffer_size = sprintf(buffer,"%s",output_buffer);
	
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
    strcpy(output_buffer, ""); //ensure that it is initialised to being empty
    nodes_controller = proc_create("popcorn_nodes", 0660, NULL, &command_channel);
    printk(KERN_INFO "Node list controller proc created");
}

void destroy_node_list_controller(void) {
    proc_remove(nodes_controller);
    printk(KERN_INFO "Node list controller proc removed");
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
