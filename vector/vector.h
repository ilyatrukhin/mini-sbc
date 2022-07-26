#ifndef __VECTOR_H__
#define __VECTOR_H__

#include <malloc.h>
#include <stdlib.h>

#define VECTOR_INIT_CAPACITY 6
#define UNDEFINE  -1
#define SUCCESS 0

//Store and track the stored data
typedef struct sVector
{
    void **items;
    int capacity;
    int size;
} vector;

int vector_size(vector *v);

int vector_resize(vector *v, int capacity);

int vector_pushback(vector *v, void *item);

int vector_set(vector *v, int index, void *item);

void *vector_get(vector *v, int index);

int vector_delete(vector *v, int index);

int vector_free(vector *v);

#endif