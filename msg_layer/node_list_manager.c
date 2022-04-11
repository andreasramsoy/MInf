/*
    This file, the node_list_manager, is responsible for manipluating the
    node list specified in node_list.h
*/
#include <popcorn/node_list.h>
#include <popcorn/kmesg_types.h>
#include <linux/kthread.h>

#include "node_list_manager.h"

char output_buffer[COMMAND_BUFFER_SIZE];

/**
 * Info on a given node. Returns NULL if it does not exist
 * @param index
 * @return void however the output_buffer is filled with pointer to a node, NULL if no node exists
*/
void node_get(int index) {
    int ip;
    struct message_node* node;
    printk(KERN_DEBUG "node_get called\n");
    node = get_node(index);
    //copy the desired output to the buffer
    /** TODO: Find correct function to translate addresses so IPv6 change is easier */
    if (node == NULL) {
        printk(KERN_DEBUG "Node could not be found so NULL is being returned\n");
        snprintf(output_buffer, COMMAND_BUFFER_SIZE, "NULL");
    }
    else {
        printk(KERN_DEBUG "Node get has been called\n");
        ip = node->address;
        snprintf(output_buffer, COMMAND_BUFFER_SIZE, "%d.%d.%d.%d %s", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, protocol_to_string(node->transport));
    }
}
EXPORT_SYMBOL(node_get);

/**
 * Checks if a node exists. Checks that a node exists at this index
 * @param int index of the node that it is checking
 * @return void however the output_buffer is filled with bool exists true if there is a node (path to the node is not null)
*/
//////////This function is not needed, just call node_get()?
/*void node_exists(int index) {
    printk(KERN_DEBUG "node_exists called\n");
    if (get_node(index)) strncpy(output_buffer, BOOL_TRUE_RETURN_STRING, sizeof(output_buffer));
    else strncpy(output_buffer, BOOL_FALSE_RETURN_STRING, sizeof(output_buffer));
}*/

/**
 * Get the first node and @return the index of the first node in the node list
 */
int forward_message_to(void) {
    struct message_node* node;
    int i;

    //check if I am the first node, if not then propagate to the first node
    if (my_nid == 0) return my_nid;
    else {
        //loop through returning the first available node
        for (i = 0; i < my_nid; i++) {
            node = get_node(i);
            if (node != NULL) {
                return i;
            }
        }
    }
    return -1;
}


/**
 * Called in a thread will listen and add nodes to the node list
 * until all nodes are added (or process is aborted)
 */
int listen_for_nodes(struct pcn_kmsg_transport* transport) {
    struct message_node* node;
    struct node_list_info_list_item* node_info;
    struct node_list_info_list_item* node_info_prev;
    int ret;
    int i;
    bool equals;
    int attempts_left = NODE_LIST_INITAL_TOKEN_ATTEMPTS;
    printk(KERN_DEBUG "Listening for nodes\n");
    printk(KERN_DEBUG "Transport with pointer %p", transport);
    printk(KERN_DEBUG "Listening for transport (1) %s\n", transport->name);

    while (number_of_nodes_to_be_added > 0 && attempts_left > 0) {
        printk(KERN_DEBUG "Nodes still to be added: %d\n", number_of_nodes_to_be_added);
        printk(KERN_DEBUG "Attempts left: %d\n", attempts_left);
        //keep accepting until all are added or no attempts left
        printk(KERN_DEBUG "Listening for transport %s\n", transport->name);
        node = create_any_node(transport);
        if (node) {
            //connection has been established - wait for message with token and nid
            while (node_info == NULL) {
                printk(KERN_DEBUG "Waiting for node info to arrive\n");
            }

            do {
                ret = down_interruptible(&node_list_info_sem);
            } while (ret);

            node_info = root_node_list_info_list;
            while (node_info->info.my_address != node->address) {
                printk(KERN_INFO "Recieved message from %d, looking for %d", node_info->info.my_address, node->address);
                printk(KERN_DEBUG "Looping through connections to find node\n");
                up(&node_list_info_sem);

                if (node_info->next == NULL) node_info = root_node_list_info_list;
                else node_info = node_info->next;

                do {
                    ret = down_interruptible(&node_list_info_sem);
                } while (ret);
            }
            up(&node_list_info_sem);
            //node_info should now contain address we're looking for
            printk(KERN_DEBUG "Token provided was: %s\n", node_info->info.token);
            printk(KERN_DEBUG "My joining token is: %s\n", joining_token);
            equals = true;
            for (i = 0; i < NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES; i++) {
                if (node_info->info.token[i] != joining_token[i]) equals = false;
            }
            if (equals) {
                //correct token so can now add to the node list and remove from node list info list

                if (get_node(node_info->info.your_nid) != NULL && get_node(node_info->info.your_nid) != get_node(my_nid)) {
                    printk(KERN_ERR "Two nodes were trying to be added to the same position! Inconsistant node list!\n");
                    /** TODO: Add some sort of reporting system? */
                }
                if (add_node_at_position(node, node_info->info.your_nid, node_info->info.token)) {
                    printk(KERN_DEBUG "Successfully added new node\n");
                    number_of_nodes_to_be_added--;
                }
                else {
                    printk(KERN_ERR "Failed to add the new node\n");
                    kfree(node);
                }


                node->index = node_info->info.your_nid;
                node->arch = node_info->info.arch;
                if (root_node_list_info_list == node_info) {
                    root_node_list_info_list = node_info->next; //skip over, doesn't matter if it's null
                }
                else {
                    node_info_prev = root_node_list_info_list;
                    while (node_info_prev->next != node_info && node_info_prev->next == NULL) {
                        node_info_prev = node_info_prev->next;
                    }
                    node_info_prev = node_info->next;
                }
                printk(KERN_DEBUG "Handled node info\n");
            }
            else {
                printk(KERN_ERR "The TOKEN did NOT match! Cannot add this node!\n");
                if (node) kfree(node);
            }
        }

        attempts_left--;
    }
    
    if (number_of_nodes_to_be_added == 0 && attempts_left > 0) {
        registered_on_popcorn_network = true; //fully integrated into system now with all nodes connected
    }
    return 0;
}
EXPORT_SYMBOL(listen_for_nodes);

/**
 * To be called either when there are no more nodes to connect
 * or when an abort is called. Stops all threads that are l
 * istening for nodes
 */
void stop_listening_threads(void) {
    struct transport_list* transports = transport_list_head;

    printk(KERN_DEBUG "Stopping listening threads\n");

    do {
        if (transports->listener) {
            kthread_stop(transports->listener);
        }
        transports = transports->next;
    } while (transports != NULL);

    printk(KERN_DEBUG "Finished stopping listening threads\n");
}
EXPORT_SYMBOL(stop_listening_threads);

void force_remove(int index) {
    //function is for debugging and testing the error detection system
    printk(KERN_DEBUG "Force removing node %d\n");

    force_remove_node(index);

    strncpy(output_buffer, "0 FORCE_REMOVED_A_NODE", sizeof(output_buffer));
    printk("Finished kicking node\n");
}
EXPORT_SYMBOL(force_remove);

void node_ping(int index, bool reply) {
    //function is for debugging and testing just to allow for a node to be kicked
    printk(KERN_DEBUG "Pinging node %d\n");

    send_node_ping_info(index, reply); //ping a node and ask for a reply

    strncpy(output_buffer, "0 PINGED_NODE", sizeof(output_buffer));
    printk("Finished pinging node\n");
}
EXPORT_SYMBOL(node_ping);

void full_check(void) {
    printk("A full check on the node list has been requested\n");

    run_full_check();

    strncpy(output_buffer, "0 FULL_CHECK_REQUESTED", sizeof(output_buffer));
    printk("Finished running full check\n");
}
EXPORT_SYMBOL(full_check);

void prelim_check(void) {
    printk("A prelim check on the node list has been requested\n");

    run_prelim_check();

    strncpy(output_buffer, "0 PRELIM_CHECK_REQUESTED", sizeof(output_buffer));
    printk("Finished running prelim check\n");
}
EXPORT_SYMBOL(prelim_check);

/**
 * Adds a new node to the node list.
 * @param char* address address of the node
 * @param char* protocol the protocol to be used for the node
 * @param bool propagate just for testing the check and correction system for the node list
 * @return void however the output_buffer is filled with the index of the newly created node in the node list (-1 if it failed)
*/
void node_add(char* address_string, char* protocol_string, int max_connections, bool propagate) {
    //convert values that can be used in the popcorn messaging layer
    uint32_t address;
    struct message_node* node;
    struct message_node* myself;
    struct pcn_kmsg_transport* protocol;
    struct transport_list* transports;
    int instigator_node_index;
    int new_node_index;
    bool success;
    int i;
    char name[40];
    char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES];

    //handle user input
    printk(KERN_DEBUG "node_add called\n");
    protocol = string_to_transport(protocol_string);
    address = in_aton(address_string);
    if (protocol == NULL) {
        printk(KERN_ERR "Wrong protocols in node add\n");
        strncpy(output_buffer, "-1 WRONG_PROTOCOL", sizeof(output_buffer));
        return;
    }

    //now add the node
    if (!registered_on_popcorn_network) {
        //not registered so joining another network
        printk(KERN_DEBUG "Joining existing popcorn network\n");


        //start by adding the instigator
        node = create_node(address, protocol);
        if (!node) {
            printk(KERN_ERR "Could not create the node for the instigator\n");
            return;
        }
        printk(KERN_DEBUG "Created the instigator node, now await node list info\n");

        while (my_nid == -1) {
            printk(KERN_DEBUG "Waiting for instigator node to send info about the node list\n");
        }

        if (root_node_list_info_list == NULL) {
            printk(KERN_ERR "Root node list info list cannot be null as it has just sent\n");
            return;
        }

        for (i = 0; i < NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES; i++) {
            token[i] = 0;
        }
        if (add_node_at_position(node, root_node_list_info_list->info.my_nid, token)) { //add the instigator node to its correct position
            number_of_nodes_to_be_added--; //the instigator node has been added so one less to worry about
            node->arch = root_node_list_info_list->info.arch; //set arch from info given
        }
        else {
            printk(KERN_ERR "The instigator node could not be added to the node list\n");
            return;
        }


        //now add myself
        printk(KERN_DEBUG "My address according to the instigator is: %d", root_node_list_info_list->info.your_address);
        myself = create_node(root_node_list_info_list->info.your_address, NULL);
        printk(KERN_DEBUG "My address saved: %d", myself->address);
        if (!myself) {
            printk(KERN_ERR "Could not create a node for myself\n");
            return;
        }
        if (!add_node_at_position(myself, root_node_list_info_list->info.your_nid, token)) {
            printk(KERN_ERR "Could not add myself to the node list\n");
            return;
        }
        memcpy(myself->token, joining_token, NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES); //set token so that all node lists are consistent


        printk(KERN_DEBUG "Node info recieved, ready to listen for connections\n");

        success = true;


        transports = transport_list_head;
        printk(KERN_DEBUG "transport list head: %p\n", transport_list_head->transport_structure);
        printk(KERN_DEBUG "transport list head name: %s\n", transport_list_head->transport_structure->name);
        while (transports != NULL && propagate && number_of_nodes_to_be_added > 0) {
            /**
             * for each transport type start listening for new nodes
             * once all nodes are accounted for then stop listening
             * if someone is bute forcing the token then also stop
             */
            sprintf(name, "transport_%s", transports->transport_structure->name);
            //transports->listener = kthread_run((listen_for_nodes)(transports->transport_structure), transports->transport_structure, name);
            listen_for_nodes(transports->transport_structure);
            
            msleep(1000);
            //kthread_stop(transports->listener);
            printk(KERN_DEBUG "Listener request made\n");

            /*if (IS_ERR(transports->listener)) {
                printk(KERN_ERR "Cannot create thread for transport listener: %s, %ld\n", transports->transport_structure->name, PTR_ERR(transports->listener));
                transports->listener = NULL;
                success = false;
                break; //didn't work so stop and abort
            }*/
            
            transports = transports->next ? transport_list_head : transports->next;
            printk(KERN_DEBUG "Moving to next transport\n");
        }
        printk(KERN_DEBUG "Outside of loop\n");

        //end all those unsuccessful transports if they failed
        if (!success) {
            if (node) kfree(node);
            /*do {

                if (transports->listener) {
                    kthread_stop(transports->listener);
                }

                transports = transports->next;
            } while (transports != NULL);*/
            printk(KERN_INFO "FAILED to register on popcorn_network\n");
        }
        else {
            registered_on_popcorn_network = true;
            printk(KERN_INFO "Successfully registered on popcorn_network\n");
        }
    }
    else {
        printk(KERN_DEBUG "Adding new node to my popcorn network\n");
        instigator_node_index = 0; //instigator is the node that starts sending messages across the network
        while (instigator_node_index < after_last_node_index && !get_node(instigator_node_index)) {
            instigator_node_index++; //loop until first non-null value
        }
        if (instigator_node_index != my_nid) {
            printk(KERN_DEBUG "The instigator node must start the command sending process, forwarding to instigator\n");
            //send_node_command_message(instigator_node_index, NODE_LIST_ADD_NODE_COMMAND, address, protocol_string, max_connections, "");
        }
        else {
            //this is the instigator node - try to add
            //then, if successful: tell the new node it's nid and forward command to other nodes
            node = create_node(address, protocol);
            if (!node) {
                printk(KERN_ERR "Failed to create new node\n");
                return; //couldn't manage so don't forward as other nodes will probably fail too
            }
            get_random_bytes(token, NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES); //random token that will be passed across popcorn so only real nodes can join
            new_node_index = add_node(node, max_connections, token, propagate);
            if (new_node_index == -1) {
                printk(KERN_ERR "Failed to add the new node\n");
                kfree(node);
                return; //couldn't manage so don't forward as other nodes will probably fail too
            }

            //node now added

            //send_to_child(my_nid, NODE_LIST_ADD_NODE_COMMAND, address, protocol_string, max_connections, token);
        }
    }

    snprintf(output_buffer, COMMAND_BUFFER_SIZE, "%d", new_node_index);
    printk(KERN_DEBUG "Done adding node\n");
}
EXPORT_SYMBOL(node_add);

/**
 * Function to instantiate a new popcorn network where this node becomes the first
 * and others can join
 * @param string address for this node (node has multiple interfaces so specify)
 */
void activate_popcorn(char* address_string) {
    struct message_node* node;
    int index;
    int i;
    char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES];
    uint32_t address = in_aton(address_string);
    printk(KERN_DEBUG "Popcorn network is being activated\n");

    if (registered_on_popcorn_network) {
        printk(KERN_ERR "Already a part of a popcorn network - cannot create a new one\n");
        goto failed_to_register;
    }
    
    my_nid = 0; //must be 0 as we are the first in the node list

    //create myself
    node = create_instigator_node(address);
    if (!node) {
        printk(KERN_ERR "Could not activate popcorn network as this node could not be created for node list\n");
        goto failed_to_register;
    }
    printk(KERN_DEBUG "Instigator node created\n");
    if (!is_myself(node)) {
        printk(KERN_ERR "The first node must be myself\n");
        goto failed_to_register;
    }

    my_nid = 0; //set this as you must be the first node
    node->index = 0;

    //add myself
    for (i = 0; i < NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES; i++) {
        token[i] = 0;
    }
    index = add_node(node, 1, token, true); //token and max connections not needed for itself
    if (index != 0) { //note it should always be zero as this is the first node to be added
        printk(KERN_ERR "The node was supposed to be put in the first position (index 0) but it was in position %d\n", index);
        goto failed_to_register;
    }

    //called is_myself which sets my_nid
    if (my_nid != index) {
        printk(KERN_ERR "my_nid should have been set to this node\n");
        goto failed_to_register;
    }
    //node is now added to the node list

    registered_on_popcorn_network = true;
    strncpy(output_buffer, "0 REGISTERED NEW POPCORN NETWORK", sizeof(output_buffer));

    return;

failed_to_register:
    printk(KERN_ERR "Failed to register new popcorn network!\n");
    if (node) {
        kfree(node);
    }
    registered_on_popcorn_network = false;
    strncpy(output_buffer, "1 FAILED TO REGISTER NETWORK", sizeof(output_buffer));
}
EXPORT_SYMBOL(activate_popcorn);

/**
 * Kills the connection and removes the given node. Destroys the connection to the given node, frees the memory that
 * it used and then deletes the pointer in the node list (replaced with a NULL pointer). Removing a node will not effect
 * any of the other nodes or the indices used to access them.
 * @param int index of the node to be accessed
 * @return void however the output_buffer is filled with true if successful false if not
*/
void node_remove(int index) {
    int first_node;
    int i;
    char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES];
    printk(KERN_DEBUG "node_remove called\n");
    int max_connections = 1; /** TODO: forward and store this value */
    if (!get_node(index)) strncpy(output_buffer, BOOL_FALSE_RETURN_STRING, sizeof(output_buffer));
    else {
        first_node = forward_message_to();
        first_node = find_first_null_pointer();

        if (registered_on_popcorn_network) {
            if (my_nid == first_node) {
                //I am the instigator so start removing
                for (i = 0; i < NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES; i++) {
                    token[i] = 0;
                }
                send_to_child(my_nid, NODE_LIST_REMOVE_NODE_COMMAND, 0, "", max_connections, token); //not all parameters are needed as
                //now that the message has been forwarded, it is safe to remove the node (without other nodes not getting the message)
                remove_node(index);
                strncpy(output_buffer, BOOL_TRUE_RETURN_STRING, sizeof(output_buffer));
            }
            else {
                //forward to the instigator node
                printk(KERN_DEBUG "Forwarding node removal to the instigator node\n");
                //send_node_command_message(first_node, NODE_LIST_REMOVE_NODE_COMMAND, 0, "", 1, ""); //0 and "" are for parameters not needed to remove a node
            }
        }
        else {
            printk(KERN_ERR "Cannot remove a node when you are not a part of a popcorn network\n");
        }
    }
    printk(KERN_DEBUG "Done handling node removal\n");
}
EXPORT_SYMBOL(node_remove);

/**
 * Fetches the address of the node.
 * @param int index the index of the node in the node list
 * @param char *address[] string that the result will be placed in
*/
void node_get_address(int index, char address[INET_ADDRSTRLEN]) {
    printk(KERN_DEBUG "node_get_address called\n");
    if (!get_node(index)) printk(KERN_ERR "Failed to get the node address, the address variable has not been updated and so has it's previous value");
    else {
        uint32_t ip = get_node(index)->address;

        //convert to string then return in the string passed by reference
        snprintf(address, COMMAND_BUFFER_SIZE, "%u.%u.%u.%u", ip & 0xFF, (ip>>8) & 0xFF, (ip>>16) & 0xFF, (ip>>24) & 0xFF);
    }
}
EXPORT_SYMBOL(node_get_address);

/**
 * Fetches the protocol used in the given node.
 * @param int index the index of the node in the node list
 * @return void however the output_buffer is filled with the protocol used as a string
*/
char* node_get_protocol(int index) {
    printk(KERN_DEBUG "node_get_protocol called\n");
    if (!get_node(index)) return "Node does not exist";
    else return get_node(index)->transport->name;
}
EXPORT_SYMBOL(node_get_protocol);

/**
 * Updates the protocol of the node requested.
 * @param int index the index of the node to be updated
 * @param char* protocol the protocol to be updated to
 * @return void however the output_buffer is filled with bool success
*/
void node_update_protocol(int index, char* protocol) {
    printk(KERN_DEBUG "node_update_protocol called\n");
    printk(KERN_ERR "node_update_protocol disabled as adding and removing is now propagated through network\n");
    /*if (!get_node(index)) strncpy(output_buffer, BOOL_FALSE_RETURN_STRING, sizeof(output_buffer));
    else {
        disable_node(index); //tear down existing connection
        get_node(index)->transport = string_to_transport(protocol); //change the protocol
        if (enable_node(index)) strncpy(output_buffer, BOOL_TRUE_RETURN_STRING, sizeof(output_buffer));
        else strncpy(output_buffer, BOOL_FALSE_RETURN_STRING, sizeof(output_buffer));
    }*/
}
EXPORT_SYMBOL(node_update_protocol);

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
    uint32_t search_term;

    printk(KERN_DEBUG "node_find called\n");
    search_term = address_string_to_int(address);

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
 * Gives the highest indexed node.
 * @return void however the output_buffer is filled with the highest index of a node that exists
*/
void node_highest_index(void) {
    printk(KERN_DEBUG "node_highest_index\n");
    snprintf(output_buffer, COMMAND_BUFFER_SIZE, "%d", after_last_node_index - 1);
}
EXPORT_SYMBOL(node_highest_index);
