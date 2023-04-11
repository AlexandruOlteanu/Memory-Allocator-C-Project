// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"
#include <stdlib.h>

#define MMAP_THRESHOLD	(128 * 1024)
#define BYTE_GROUP_MEASURE (1 << 3)
#define block_meta_size (sizeof(block_meta))

struct data_blocks {
	block_meta *head;
} data;

block_meta *get_last_block() {
	block_meta *node = data.head;
	while (node->next != NULL) {
		node = node->next;
	}
	return node;
}

block_meta *get_first_free_data_block(size_t size) {

	block_meta *node = data.head;
	block_meta *result = NULL;
	while (node != NULL) {
		if (node->status == STATUS_FREE && node->size >= size) {
			result = node;
			break;
		} else {
			node = node->next;
		}
	}

	return result;
}


int added_padding(int value) {
	return (value / BYTE_GROUP_MEASURE) * BYTE_GROUP_MEASURE + (value % BYTE_GROUP_MEASURE != 0) * BYTE_GROUP_MEASURE;
}

int get_full_data_block_size(int value) {
	return added_padding(value + block_meta_size);
}

void *allocate_memory_by_target(size_t size, int target) {
	if (!size) {
    	return NULL;
	}

    if (get_full_data_block_size(size) < target) {

		if (data.head == NULL) {
        	void *memory = sbrk(MMAP_THRESHOLD);
			block_meta *node = memory;
			node->size = added_padding(size);
			node->status = STATUS_ALLOC;
			node->next = NULL;
			data.head = node;
			return (void *)((char *)memory + block_meta_size);
		}
		else {
			block_meta *answer = get_first_free_data_block(added_padding(size));
			if (answer != NULL) {
				answer->status = STATUS_ALLOC;

				if (answer->size - added_padding(size) >= block_meta_size + 1) {
					block_meta *node = (char *)answer + get_full_data_block_size(size);
					node->size = answer->size - get_full_data_block_size(size);
					node->status = STATUS_FREE;
					answer->size = added_padding(size);
					node->next = answer->next;
					answer->next = node;
				}

				return (answer + 1);
			}
			else {
				block_meta *last = get_last_block();
				if (last->status == STATUS_FREE) {
					void *memory = sbrk(added_padding(size - last->size));
					last->size += added_padding(size - last->size);
					last->status = STATUS_ALLOC;
					return (last + 1);
				}
				else {
					void *memory = sbrk(get_full_data_block_size(size));
					block_meta *node = memory;
					node->size = added_padding(size);
					node->status = STATUS_ALLOC;
					node->next = NULL;
					block_meta *last = get_last_block();
					last -> next = node;
					last = node;
					return (void *)((char *)memory + block_meta_size);
				}
			}
		}
        
    } else {
		block_meta *node;
        void *memory = mmap(NULL, get_full_data_block_size(size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		node = memory;
		node->size = added_padding(size);
		node->status = STATUS_MAPPED;
		node->next = NULL;
		if (data.head == NULL) {
			data.head = node;
		}
		else {
			block_meta *last = get_last_block();
			last->next = node;
		}
        return (void *)((char *)memory + sizeof(struct block_meta));
    }
}

void *os_malloc(size_t size) {
   return allocate_memory_by_target(size, MMAP_THRESHOLD);
}

void os_free(void *ptr) {
    if (ptr != NULL) {

		block_meta *aux = data.head, *prev = NULL;

		while (aux + 1 != ptr) {
			prev = aux;
			aux = aux->next;
		}

		if (aux->status == STATUS_ALLOC) {
			aux->status = STATUS_FREE;
			if (prev != NULL && prev->status == STATUS_FREE) {
				prev->size += aux->size + block_meta_size;
				prev->next = aux->next;
				aux = prev;
			}
			if (aux -> next != NULL && aux->next->status == STATUS_FREE) {
				aux->size += aux->next->size + block_meta_size;
				aux->next = aux->next->next;
			}
		} 
		else {
			if (aux == data.head) {
				data.head = data.head->next;
			}
			else {
				prev->next = aux->next;
			}

			size_t size = aux->size;
			munmap(aux, size + block_meta_size);
		}
    }
}

void *os_calloc(size_t nmemb, size_t size)
{
	size = nmemb * size;
	void *ptr = allocate_memory_by_target(size, getpagesize());
  	memset(ptr, 0, size);
  	return ptr;
}

void *os_realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return allocate_memory_by_target(size, MMAP_THRESHOLD);
    }

    if (size == 0) {
        os_free(ptr);
        return NULL;
    }

    struct block_meta *aux = (struct block_meta *)ptr - 1;

    if (added_padding(size) <= aux->size) {

		if (aux->status == STATUS_MAPPED) {
			if (added_padding(size) < MMAP_THRESHOLD) {
                size_t new_size = added_padding(size);
                void *new_memory = sbrk(MMAP_THRESHOLD);
                if (new_memory == (void *)-1) {
                    return NULL;
                }
                struct block_meta *new_block = (block_meta *)new_memory;
                new_block->size = new_size;
                new_block->status = STATUS_ALLOC;
                new_block->next = aux->next;

                if (data.head == aux) {
                    data.head = new_block;
                } else {
                    block_meta *prev = data.head;
                    while (prev->next != aux) {
                        prev = prev->next;
                    }
                    prev->next = new_block;
                }

                memcpy((char *)new_memory + block_meta_size, ptr, new_size);
                munmap(aux, aux->size + block_meta_size);
                return (char *)new_memory + block_meta_size;
            } 
		}
		else
			if (aux->size - added_padding(size) >= block_meta_size + 1) {
				block_meta *new_node = (char *)aux + get_full_data_block_size(size);
				new_node->size = aux->size - get_full_data_block_size(size);
				new_node->status = STATUS_FREE;
				aux->size = added_padding(size);
				new_node->next = aux->next;
				aux->next = new_node;
			}
        	return ptr;
    } else if (aux->next && aux->next->status == STATUS_FREE && aux->size + block_meta_size + aux->next->size >= added_padding(size)) {
        aux->size = aux->size + block_meta_size + aux->next->size;
        aux->next = aux->next->next;
        return ptr;
    } else {
        void *new_ptr = allocate_memory_by_target(size, MMAP_THRESHOLD);
        if (new_ptr) {
            memcpy(new_ptr, ptr, aux->size);
            os_free(ptr);
        }
        return new_ptr;
    }
}
