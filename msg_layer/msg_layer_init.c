/**
 * Calls and sets up the TCP and other protocols to run popcorn
 * without being tied to a particular transfer protocol
 */

static void __exit exit_kmsg(void) {
	MSGPRINTK("Exiting Popcorn messaging layer...\n");

	MSGPRINTK("Popcorn messaging layer: destroying node list controller\n");
	destroy_node_list_controller(); //call first to avoid user changing node list while destroying it

	MSGPRINTK("Popcorn messaging layer: removing peers proc\n");
	proc_remove(proc_entry);

	MSGPRINTK("Popcorn messaging layer: destroying node list\n");
    destroy_node_list()

	MSGPRINTK("Popcorn messaging layer has been unloaded\n");
}

static int __init init_kmsg(void) {
	MSGPRINTK("Loading Popcorn messaging layer...\n");


	MSGPRINTK("Popcorn messaging layer: initialising node list\n");
	initialise_node_list();

	MSGPRINTK("Popcorn messaging layer: initialising peers proc\n");
	peers_init();
	
	MSGPRINTK("Popcorn messaging layer: initialising node list controller\n");
	initialise_node_list_controller(); //allow user to change nodes

    return 0;
}

module_init(init_kmsg);
module_exit(exit_kmsg);
MODULE_LICENSE("GPL");
