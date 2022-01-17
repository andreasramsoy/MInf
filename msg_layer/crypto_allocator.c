#include <sys/eventfd.h>


// 1. generate file descriptor
// 2. loop until a message appears
// 3. allocate/deallocate crypto structure and pass address back (does this need to be kernel space)

#define POPCORN_AES_KEY_SIZE 256
#define MAX_MESSAGE_SIZE_BYTES 200
#define ALLOCATE_COMMAND 0
#define DELLOCATE_COMMAND 1


//Daemon
struct request {
    ...
    struct completion;
};

struct linked_list {
    struct crypto_blkcipher *value;
    struct linked_list *next;
};

struct linked_list *list_head;


int add_to_list(struct crypto_blkcipher *blkcipher, int id) {
    struct linked_list *list_node;

    if (list_head == NULL) {
        list_head = malloc(sizeof(struct linked_list));
        if (list_head == NULL) {
            print("Could not allocate first item to list\n");
            return -1;
        }
        list_node = list_head;
    }
    else {
        list_node = list_head
        while (list_node->next == NULL) {
            list_node = list_node->next;
        }
        //at end of list so append
        list_node->next = malloc(sizeof(struct linked_list));
        if (list_node->next == NULL) {
            print("Could not allocate new item to list\n");
            return -1;
        }
        list_node = list_node->next;
    }

    //now add values
    list_node->value = blkcipher;
    list_node->id = id;
    list_node->next = NULL; //end of list
    return list_node;
}

int remove_from_list(id) {
    struct linked_list *node_list;
    struct linked_list *node_prev;
    struct crypto_blkcipher *return_value;

    if (list_head == NULL) {
        print("There are no allocators to deallocate\n")
        return NULL;
    }
    else if (list_head->id != id && list_head->next == NULL) {
        print("The only allocator did not have the id %d, do did not deallocate\n", id);
        return NULL;
    }
    else if (list_head->next == NULL) {
        //must have the correct id and no other nodes
        return_value = list_head->value;
        free(list_head);
        list_head = NULL;
        return return_value;
    }
    else if (list_head->id == id) {
        //first element is the one we are looking for
        return_value = list_head->value;
        node_list = list_head;
        list_head = node_list->next; //move along one
        free(node_list);
        return return_value;
    }
    else {
        //must be multiple elements in list
        node_prev = list_head;
        node_list = list_head->next;

        while (node_list->next != NULL && node_list->id != id) {
            node_prev = node_list;
            node_list = node_list->next;
        }

        //check why you exitted the loop, either you're at the node or you checked all
        if (node_list->next != NULL) {
            print("Did not find the node with id %d\n", id);
            return NULL;
        }
        else {
            //you've found it
            node_prev->next = node_list->next; //skip over the node to be deleted
            return_value = node_list->value;
            free(node_list);
            print("Freed value from list\n");
            return return_value;
        }
    }
}

struct crypto_blkcipher *allocate_blkcipher(void) {
    keysize = POPCORN_AES_KEY_SIZE;
	algo = "xts(aes)";

	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return NULL;
	}
    else {
        return tfm;
    }
}

int deallocate_blkcipher(struct crypto_blkcipher *tfm) {
    //previously checked if null so just release
	crypto_free_blkcipher(tfm);
    return 0;
}

int message_popcorn(char* message[MAX_MESSAGE_SIZE_BYTES]) {
    //send message to popcorn proc
}

//popcorn thread:
spin_lock(requests_lock);
queue_request(r, requests_list);
wait_completion(r.wait);


int main(int argc, void* argv[]) {
    struct list_head requests_list;
    spinlock_t requests_lock;
    char message[MAX_MESSAGE_SIZE_BYTES];
    struct crypto_blkcipher* blk_cipher;
    eventfd_t efd = eventfd(0, 0);
    list_head = NULL;

    if (efd == -1) {
        printf("Could not create event file descriptor\n");
        return efd;
    }

    printf("Starting crypto allocator, do not stop before all allocators have been deallocated\n");

    while (epoll(epd)) {
        spin_lock(requests_lock);

        s = read(efd, &message, MAX_MESSAGE_SIZE_BYTES);
        printf("Message was: %s", message);
        snscanf(message, "%d %d", &command, &id);

        switch(command) {
            case ALLOCATE_COMMAND:
                blk_cipher = allocate_blkcipher();
                if (blk_cipher == NULL) {
                    //failed
                }
                else {
                    add_to_list(blk_cipher, id);
                    //transmit pointer
                }
            case DEALLOCATE_COMMAND:
                blk_cipher = remove_from_list(id);
                if (blk_cipher == NULL) {
                    print("This block cipher was not already allocated, failed to deallocate\n");
                    //return error
                }
                else {
                    deallocate_blk_cipher(blk_cipher);
                }
        }
        // r=get_request(requests_list);
        // handle(r);
        // complete(r->wait)
        spin_unlock(requests_lock);
    }
    return 0;
}

///////////////// needs to send a reply to a proc