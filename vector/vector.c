#include "vector.h"

int vector_size(vector *v)
{
    int size = UNDEFINE;
    if(v)
    {
        size = v->size;
    }
    return size;
}

int vector_resize(vector *v, int capacity)
{
    int  status = UNDEFINE;
    if(v)
    {
        void **items = realloc(v->items, sizeof(void *) * capacity);
        if (items)
        {
            v->items = items;
            v->capacity = capacity;
            status = SUCCESS;
        }
    }
    return status;
}

int vector_pushback(vector *v, void *item)
{
    int  status = UNDEFINE;
    if(v)
    {
        if (v->capacity == v->size)
        {
            status = vector_resize(v, v->capacity * 2);
            if(status != UNDEFINE)
            {
                v->items[v->size++] = item;
            }
        }
        else
        {
            v->items[v->size++] = item;
            status = SUCCESS;
        }
    }
    return status;
}

int vector_set(vector *v, int index, void *item)
{
    int  status = UNDEFINE;
    if(v)
    {
        if ((index >= 0) && (index < v->size))
        {
            v->items[index] = item;
            status = SUCCESS;
        }
    }
    return status;
}

void *vector_get(vector *v, int index)
{
    void *readData = NULL;
    if(v)
    {
        if ((index >= 0) && (index < v->size))
        {
            readData = v->items[index];
        }
    }
    return readData;
}

int vector_delete(vector *v, int index)
{
    int  status = UNDEFINE;
    int i = 0;
    if(v)
    {
        if ((index < 0) || (index >= v->size))
            return status;
        v->items[index] = NULL;
        for (i = index; (i < v->size - 1); ++i)
        {
            v->items[i] = v->items[i + 1];
            v->items[i + 1] = NULL;
        }
        v->size--;
        if ((v->size > 0) && ((v->size) == (v->capacity / 4)))
        {
            vector_resize(v, v->capacity / 2);
        }
        status = SUCCESS;
    }
    return status;
}

int vector_free(vector *v)
{
    int  status = UNDEFINE;
    if(v)
    {
        free(v->items);
        v->items = NULL;
        status = SUCCESS;
    }
    return status;
}