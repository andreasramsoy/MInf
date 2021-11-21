#ifndef __POPCORN_SOCKET_TRANSPORT_H__
#define __POPCORN_SOCKET_TRANSPORT_H__

#define PORT 30467
#define MAX_SEND_DEPTH	1024
#define NIPQUAD(addr) ((unsigned char *)&addr)[0],((unsigned char *)&addr)[1],((unsigned char *)&addr)[2],((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

enum {
	SEND_FLAG_POSTED = 0,
};

//interface for the messaging layer
extern struct pcn_kmsg_transport transport_socket;

extern void sock_kmsg_put(struct pcn_kmsg_message *msg);
extern struct pcn_kmsg_message *sock_kmsg_get(size_t size);
extern void sock_kmsg_put(struct pcn_kmsg_message *msg);


/***********************************************
 * This is the interface for message layer
 ***********************************************/
extern int sock_kmsg_send(int dest_nid, struct pcn_kmsg_message *msg, size_t size);
extern int sock_kmsg_post(int dest_nid, struct pcn_kmsg_message *msg, size_t size);
extern void sock_kmsg_done(struct pcn_kmsg_message *msg);

extern void sock_kmsg_stat(struct seq_file *seq, void *v);
extern int __sock_connect_to_server(struct message_node* node);
extern int __sock_accept_client(struct message_node* node);
extern int __sock_listen_to_connection(void);
extern bool kill_node_sock(struct message_node* node);
extern bool init_node_sock(struct message_node* node);
extern int exit_sock(void);

extern int init_sock(void);
#endif