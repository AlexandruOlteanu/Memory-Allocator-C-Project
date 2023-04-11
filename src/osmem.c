// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"
#include <stdlib.h>

#define MMAP_THRESHOLD	(128 * 1024)


struct block_meta *head;
struct block_meta *last;

struct block_meta *find_reusable_block(size_t size) {

	struct block_meta *aux = head;
	while (aux != NULL) {
		if (aux->status == STATUS_FREE && aux->size >= size) {
			return aux;
		}
		aux = aux->next;
	}
	return NULL;
}

void *my_alloc(size_t size, int limit) {
	 if (size == 0) {
        return NULL;
    } else if (size + sizeof(struct block_meta) + (8 - size % 8) % 8 < limit) {

		if (head == NULL) {
        	void *memory = sbrk(MMAP_THRESHOLD);
			struct block_meta *node = memory;
			node->size = size + (8 - size % 8) % 8;
			node->status = STATUS_ALLOC;
			node->next = NULL;
			head = last = node;
			if (memory == (void *) -1) {
            	return NULL;
			} else {
				return (void *)((char *)memory + sizeof(struct block_meta));
			}
		}
		else {
			struct block_meta *answer = find_reusable_block(size + (8 - size % 8) % 8);
			if (answer != NULL) {
				answer->status = STATUS_ALLOC;

				if (answer->size - (size + (8 - size % 8) % 8) >= sizeof(struct block_meta) + 1) {
					struct block_meta *node = (char *)answer + sizeof(struct block_meta) + (size + (8 - size % 8) % 8);
					node->size = answer->size - (size + (8 - size % 8) % 8) - sizeof(struct block_meta);
					node->status = STATUS_FREE;
					answer->size = size + (8 - size % 8) % 8;
					node->next = answer->next;
					answer->next = node;
				}

				return (answer + 1);
			}
			else {
				if (last->status == STATUS_FREE) {
					void *memory = sbrk((size - last->size) + (8 - (size - last->size) % 8) % 8);
					last->size += (size - last->size) + (8 - (size - last->size) % 8) % 8;
					last->status = STATUS_ALLOC;
					return (last + 1);
				}
				else {
					void *memory = sbrk(size + sizeof(struct block_meta) + (8 - size % 8) % 8);
					struct block_meta *node = memory;
					node->size = size + (8 - size % 8) % 8;
					node->status = STATUS_ALLOC;
					node->next = NULL;
					last -> next = node;
					last = node;
					if (memory == (void *) -1) {
						// Memory allocation failed
						return NULL;
					} else {
						return (void *)((char *)memory + sizeof(struct block_meta));
					}
				}
			}
		}
        
    } else {
        // Allocate memory using mmap()
		struct block_meta *node;
        void *memory = mmap(NULL, size + sizeof(struct block_meta) + (8 - size % 8) % 8, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		node = memory;
		node->size = size + (8 - size % 8) % 8;
		node->status = STATUS_MAPPED;
		node->next = NULL;
		if (head == NULL) {
			head = last = node;
		}
		else {
			last->next = node;
			last = node;
		}
        if (memory == MAP_FAILED) {
            // Memory allocation failed
            return NULL;
        } else {
            // Store the size of the allocated memory at the beginning of the block
            // *((size_t *)memory) = size;
            return (void *)((char *)memory + sizeof(struct block_meta));
        }
    }
}

void *os_malloc(size_t size) {
   return my_alloc(size, MMAP_THRESHOLD);
}

void os_free(void *ptr) {
    if (ptr != NULL) {
        // Determine the size of the allocated memory
		
		struct block_meta *aux = head, *prev = NULL;

		while (aux + 1 != ptr) {
			prev = aux;
			aux = aux->next;
		}

		if (aux->status == STATUS_ALLOC) {
			aux->status = STATUS_FREE;
			if (prev != NULL && prev->status == STATUS_FREE) {
				prev->size += aux->size + sizeof(struct block_meta);
				prev->next = aux->next;
				aux = prev;
			}
			if (aux -> next != NULL && aux->next->status == STATUS_FREE) {
				aux->size += aux->next->size + sizeof(struct block_meta);
				aux->next = aux->next->next;
			}
			last = head;
			while (last -> next != NULL) {
				last = last->next;
			} 

		} else {
			
			if (aux == head) {
				head = head->next;
			}
			else {
				prev->next = aux->next;
			}

			size_t size = aux->size;
			munmap(aux, size + sizeof(struct block_meta));
		}
    }
}

void *os_calloc(size_t nmemb, size_t size)
{
	size = nmemb * size;
	void *ptr = my_alloc(size, getpagesize());
  	memset(ptr, 0, size);
  	return ptr;
}

void *os_realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return my_alloc(size, MMAP_THRESHOLD);
    }

    if (size == 0) {
        os_free(ptr);
        return NULL;
    }

    struct block_meta *aux = (struct block_meta *)ptr - 1;

    if (size + (8 - size % 8) % 8 <= aux->size) {
        // If the new size is smaller than the current block size, consider shrinking the block

		if (aux->status == STATUS_MAPPED) {
			if (size + (8 - size % 8) % 8 < MMAP_THRESHOLD) {
                size_t new_size = size + (8 - size % 8) % 8;
                void *new_memory = sbrk(MMAP_THRESHOLD);
                if (new_memory == (void *)-1) {
                    return NULL;
                }
                struct block_meta *new_block = (struct block_meta *)new_memory;
                new_block->size = new_size;
                new_block->status = STATUS_ALLOC;
                new_block->next = aux->next;

                if (head == aux) {
                    head = new_block;
                } else {
                    struct block_meta *prev = head;
                    while (prev->next != aux) {
                        prev = prev->next;
                    }
                    prev->next = new_block;
                }

                memcpy((char *)new_memory + sizeof(struct block_meta), ptr, new_size);
                munmap(aux, aux->size + sizeof(struct block_meta));
                return (char *)new_memory + sizeof(struct block_meta);
            } 
		}
		else
			if (aux->size - (size + (8 - size % 8) % 8) >= sizeof(struct block_meta) + 1) {
				struct block_meta *new_node = (char *)aux + sizeof(struct block_meta) + (size + (8 - size % 8) % 8);
				new_node->size = aux->size - (size + (8 - size % 8) % 8) - sizeof(struct block_meta);
				new_node->status = STATUS_FREE;
				aux->size = size + (8 - size % 8) % 8;
				new_node->next = aux->next;
				aux->next = new_node;
			}

        return ptr;
    } else if (aux->next && aux->next->status == STATUS_FREE && aux->size + sizeof(struct block_meta) + aux->next->size >= size + (8 - size % 8) % 8) {
        // If the next block is free and large enough, extend the current block
        aux->size = aux->size + sizeof(struct block_meta) + aux->next->size;
        aux->next = aux->next->next;

        return ptr;
    } else {
        // Allocate a new block and copy the data
        void *new_ptr = my_alloc(size, MMAP_THRESHOLD);
        if (new_ptr) {
            memcpy(new_ptr, ptr, aux->size);
            os_free(ptr);
        }

        return new_ptr;
    }
}
