#include "osmem.h"
#include "helpers.h"
#include <stdlib.h>

#define MMAP_THRESHOLD	(128 * 1024)
#define BYTE_GROUP_MEASURE (1 << 3)
#define block_meta_size (sizeof(block_meta))

struct data_blocks {
	block_meta *head;
} data;

block_meta *get_last_block(void)
{
	block_meta *current = data.head;

	while (current->next != NULL)
		current = current->next;
	return current;
}

block_meta *get_first_free_data_block(size_t size)
{
	block_meta *current = data.head;
	block_meta *result = NULL;

	while (current != NULL) {
		if (current->size >= size && current->status == STATUS_FREE) {
			result = current;
			break;
		}
		current = current->next;
	}

	return result;
}

void find_ptr_and_prev(block_meta **current, void *ptr, block_meta **prev)
{
	*current = data.head;
	while ((*current) + 1 != ptr) {
		*prev = *current;
		*current = (*current)->next;
	}
}


int added_padding(int value)
{
	return (value / BYTE_GROUP_MEASURE) * BYTE_GROUP_MEASURE + (value % BYTE_GROUP_MEASURE != 0) * BYTE_GROUP_MEASURE;
}

int get_full_data_block_size(int value)
{
	return added_padding(value + block_meta_size);
}

block_meta *find_first_allocated(void)
{
	block_meta *current = data.head;
	block_meta *result = NULL;

	while (current != NULL) {
		if (current->status == STATUS_ALLOC || current->status == STATUS_FREE) {
			result = current;
			break;
		}
		current = current->next;
	}
	return result;
}

void *allocate_memory_sbrk(size_t size)
{
	if (!size)
		return NULL;

	block_meta *first_allocated = find_first_allocated();

	if (first_allocated == NULL) {
		void *full_data = sbrk(MMAP_THRESHOLD);
		block_meta *current = full_data;

		current->size = added_padding(size);
		current->status = STATUS_ALLOC;
		current->next = NULL;
		if (data.head == NULL) {
			data.head = current;
		} else {
			current->next = data.head->next;
			data.head->next = current;
		}
		void *data_memory = (const char *)full_data + block_meta_size;
		return data_memory;
	}
	block_meta *answer = get_first_free_data_block(added_padding(size));

	if (answer != NULL) {
		answer->status = STATUS_ALLOC;

		if (answer->size - added_padding(size) >= block_meta_size + 1) {
			block_meta *current = (block_meta *)((const char *)answer + get_full_data_block_size(size));

			current->status = STATUS_FREE;
			current->next = answer->next;
			answer->next = current;
			current->size = answer->size - get_full_data_block_size(size);
			answer->size = added_padding(size);
		}
		void *data_memory = (char *)answer + block_meta_size;

		return data_memory;
	}
	block_meta *last = get_last_block();

	if (last->status == STATUS_FREE) {
		sbrk(added_padding(size - last->size));
		last->status = STATUS_ALLOC;
		last->size += added_padding(size - last->size);
		void *data_memory = (char *)last + block_meta_size;

		return data_memory;
	}
	void *full_data = sbrk(get_full_data_block_size(size));
	block_meta *current = full_data;

	current->status = STATUS_ALLOC;
	current->size = added_padding(size);
	current->next = NULL;
	last->next = current;
	last = current;
	void *data_memory = (char *)full_data + block_meta_size;

	return data_memory;
}

void *allocate_memory_mmap(size_t size)
{
	if (!size)
		return NULL;

	block_meta *current = NULL;
	void *full_data = mmap(NULL, get_full_data_block_size(size), PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	current = full_data;
	current->status = STATUS_MAPPED;
	current->size = added_padding(size);
	current->next = NULL;
	if (data.head == NULL) {
		data.head = current;
	} else {
		block_meta *last = get_last_block();

		last->next = current;
	}
	void *data_memory = (char *)full_data + block_meta_size;

	return data_memory;
}

void *os_malloc(size_t size)
{
	void *result = NULL;

	if (get_full_data_block_size(size) < MMAP_THRESHOLD)
		result = allocate_memory_sbrk(size);
	else
		result = allocate_memory_mmap(size);
	return result;
}

void os_free(void *ptr)
{
	if (ptr != NULL) {
		block_meta *current = NULL, *prev = NULL;

		find_ptr_and_prev(&current, ptr, &prev);
		if (current->status == STATUS_MAPPED) {
			if (current == data.head)
				data.head = data.head->next;
			else
				prev->next = current->next;
			size_t size = current->size;

			munmap(current, size + block_meta_size);
		} else {
			current->status = STATUS_FREE;
			if (prev != NULL && prev->status == STATUS_FREE) {
				prev->size += current->size + block_meta_size;
				prev->next = current->next;
				current = prev;
			}
			if (current->next != NULL && current->next->status == STATUS_FREE) {
				current->size += current->next->size + block_meta_size;
				current->next = current->next->next;
			}
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;
	void *result = NULL;

	if (get_full_data_block_size(total_size) < getpagesize())
		result = allocate_memory_sbrk(total_size);
	else
		result = allocate_memory_mmap(total_size);
	memset(result, 0, total_size);
	return result;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL) {
		if (get_full_data_block_size(size) < MMAP_THRESHOLD)
			return allocate_memory_sbrk(size);
		else
			return allocate_memory_mmap(size);
	}

	if (!size) {
		os_free(ptr);
		return NULL;
	}

	block_meta *aux = (block_meta *)ptr - 1;

	if (added_padding(size) <= aux->size) {

		if (aux->status == STATUS_MAPPED) {
			if (added_padding(size) < MMAP_THRESHOLD) {
				size_t new_size = added_padding(size);
				void *new_memory = sbrk(MMAP_THRESHOLD);

				if (new_memory == (void *)-1)
					return NULL;
				block_meta *new_block = (block_meta *)new_memory;

				new_block->size = new_size;
				new_block->status = STATUS_ALLOC;
				new_block->next = aux->next;

				if (data.head == aux) {
					data.head = new_block;
				} else {
					block_meta *prev = data.head;

					while (prev->next != aux)
						prev = prev->next;
					prev->next = new_block;
				}

				memcpy((char *)new_memory + block_meta_size, ptr, new_size);
				munmap(aux, aux->size + block_meta_size);
				return (char *)new_memory + block_meta_size;
			}
		} else
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
		void *result = NULL;

		if (get_full_data_block_size(size) < MMAP_THRESHOLD)
			result = allocate_memory_sbrk(size);
		else
			result = allocate_memory_mmap(size);
		if (result) {
			memcpy(result, ptr, aux->size);
			os_free(ptr);
		}
		return result;
	}
}
