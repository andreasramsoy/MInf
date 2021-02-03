#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include "node_list_manager.h"

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
}

void destroy_node_list_controller(void) {
    proc_remove(nodes_controller);
}
