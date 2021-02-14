#ifndef __POPCORN_TRANSPORT_PROTOCOLS_H__
#define __POPCORN_TRANSPORT_PROTOCOLS_H__



/**
 * Configurations of specific protocols should be defined in this file
*/

struct pcn_kmsg_transport tcp_transport_structure = { //copied the tcp socket
        .name = "socket",
        .features = 0,

        .get = sock_kmsg_get,
        .put = sock_kmsg_put,
        .stat = sock_kmsg_stat,

        .send = sock_kmsg_send,
        .post = sock_kmsg_post,
        .done = sock_kmsg_done,
    };

static struct socket *tcp_sock_listen = NULL;

static int __init tcp_listen(void)
{
	int ret;
	struct sockaddr_in addr;

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &tcp_sock_listen);
	if (ret < 0) {
		printk(KERN_ERR "Failed to create socket, %d", ret);
		return ret;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(PORT);

	ret = kernel_bind(tcp_sock_listen, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		printk(KERN_ERR "Failed to bind socket, %d\n", ret);
		goto out_release;
	}

	ret = kernel_listen(tcp_sock_listen, node_list_length);
	if (ret < 0) {
		printk(KERN_ERR "Failed to listen to connections, %d\n", ret);
		goto out_release;
	}

	MSGPRINTK("Ready to accept incoming connections\n");
	return 0;

out_release:
	sock_release(tcp_sock_listen);
	tcp_sock_listen = NULL;
	return ret;
}

#endif