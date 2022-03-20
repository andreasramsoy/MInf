#ifndef __POPCORN_NODE_LIST_MANAGER_H__
#define __POPCORN_NODE_LIST_MANAGER_H__

/*
    This file, the node_list_manager.h, is responsible for manipluating the
    node list specified in node_list.h
*/

#include <popcorn/node_list.h>
#include <popcorn/kmesg_types.h>
#include <linux/kthread.h>

/*
 * Note that sscanfs have a max size of 200 (cannot use #define variable for them)
 * Update them to ensure safe from buffer overflows
 */
#define COMMAND_BUFFER_SIZE 200 //unlikely to come close to this for adjusting popcorn nodes
#define BOOL_TRUE_RETURN_STRING "1" //////////////////////////////////////////////////////////////
#define BOOL_FALSE_RETURN_STRING "0" /////////////////////////////////////////////////////////////

extern char output_buffer[COMMAND_BUFFER_SIZE];

extern void node_get(int index);
extern int listen_for_nodes(struct pcn_kmsg_transport* transport);
extern void stop_listening_threads(void);
extern void full_check(void);
extern void node_add(char* address_string, char* protocol_string, int max_connections);
extern void activate_popcorn(char* address_string);
extern void node_remove(int index);
extern void node_get_address(int index, char address[INET_ADDRSTRLEN]);
extern char* node_get_protocol(int index);
extern void node_update_protocol(int index, char* protocol);
extern void node_highest_index(void);
extern void force_remove(int index);
extern void node_ping(int index);

#endif
