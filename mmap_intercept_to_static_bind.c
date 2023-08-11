//gcc -O2 -fPIC -shared mmap_intercept.c -o mmap_intercept.so -lsyscall_intercept -lnuma

//export APP="<<your_app>>"

//LD_PRELOAD=./mmap_intercept.so <<your_app>>

#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <errno.h>
#include <stdio.h>
#include <execinfo.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#define _GNU_SOURCE
#include <pthread.h>
#include <sys/resource.h>
#include <numaif.h>
#include <sys/mman.h>
#define SIZE 4096               // callstack string size
#define CHUNK_SIZE 1000001536UL  // chunk size aligned with pages of 4096 bytes
#define DRAM 1
#define CXL  2


FILE *g_fp = NULL;
FILE *fp_bind = NULL;

char g_line[SIZE];
char call_stack[SIZE];

pthread_mutex_t g_count_mutex;
unsigned long g_call_stack_vector[SIZE];

//First line is the number of objects to bind
void read_parameters_for_binding(void)
{
    int call_stack_size;
    int i;

    fp_bind = fopen("/store/hmem23/static_mapping.txt", "r");
    if (fp_bind == NULL)
    {
        fprintf(stderr, "Error open bind text!\n");
    }
    fscanf(fp_bind, "%d\n", &call_stack_size);
    for (i = 0; i < call_stack_size; i++)
    {
        fscanf(fp_bind, "%lu\n", &g_call_stack_vector[i]);
    }
    g_call_stack_vector[i] = -1;
    fclose(fp_bind);
}

int check_address(unsigned long call_stack_hash)
{
    int i = 0;
    while (g_call_stack_vector[i] != -1)
    {
        if (g_call_stack_vector[i] == call_stack_hash)
        {
            return 1;
        }
        i++;
    }
    return 0;
}

long int hash(char *word)
{
    unsigned int hash = 0;
    for (int i = 0; word[i] != '\0'; i++)
    {
        hash = 31 * hash + word[i];
    }
    // return hash % TABLE_SIZE;
    return abs(hash);
}

void redirect_stdout(char *filename)
{
    int fd;
    if ((fd = open(filename, O_CREAT | O_WRONLY, 0666)) < 0)
    {
        perror(filename);
        exit(1);
    }
    close(1);
    if (dup(fd) != 1)
    {
        fprintf(stderr, "Unexpected dup failure\n");
        exit(1);
    }
    close(fd);

    g_fp = fopen("/tmp/call_stack_bind.txt", "w+");
    if (g_fp == NULL)
    {
        printf("Error when try to use fopen!!\n");
    }
}

void get_call_stack()
{
    char *addr;
    char **strings;
    char *p;
    const char *substring = getenv("APP");
    int static mmap_id = 0;
    int nptrs;
    int i;
    int k = 0;
    void *buffer[SIZE];
    size_t len = SIZE;
    ssize_t read;

    nptrs = backtrace(buffer, SIZE);
    backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO);
    fflush(stdout);

    // while ((read = getline(&g_line, &len, g_fp)) != -1) {
    for (int callstack_line_index = 0; callstack_line_index < nptrs; callstack_line_index++)
    {
 //read = getline(&g_line, &len, g_fp);
 p = fgets(g_line,len,g_fp);
 if(p == NULL){
 fprintf(stderr,"fgets NULL\n");
 return;
 }
        p = strstr(g_line, substring);
        if (p)
        {
            //fprintf(stderr,"ENTROU:%s\n", g_line);
            for (i = 0; i < len; i++)
            {
                if (g_line[i] == '[')
                    break;
            }
            for (i = i + 1; i < len; i++)
            {
                if (g_line[i] == ']')
                    break;
                call_stack[k] = g_line[i];
                k++;
            }
            call_stack[k] = ':';
            k++;
        }
       // else{
       //      fprintf(stderr,"NAO ENTROU:%s\n", g_line);
       // }
    }
    call_stack[k - 1] = '\0';
}

static int
hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result)
{
    char size[SIZE]; // chunk size
    char obj_size[SIZE]; //object size
    char chunk_index[3];
    char temp_call_stack[SIZE];
    char call_stack[SIZE] = "";
    int static mmap_id = 0;
    int i;
    int total_obj;
    unsigned long long remnant_size;
    unsigned long call_stack_hash;
    unsigned long g_nodemask;
    struct timespec ts;
    int flags;

    flags = (int) arg3;
    sprintf(obj_size, ":%ld", arg1);

    if (syscall_number == SYS_mmap)
    {
 if ((flags & MAP_ANONYMOUS) != MAP_ANONYMOUS) {
 return 1;
  }

 if ((flags & MAP_STACK) == MAP_STACK) {
    return 1;
 }

        *result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);

        pthread_mutex_lock(&g_count_mutex);
        clock_gettime(CLOCK_MONOTONIC, &ts);
        get_call_stack();
        // fprintf(stderr,"%s,%d\n",call_stack,hash(call_stack));

        if (arg1 > CHUNK_SIZE)
        {
            i = 0;
            total_obj = arg1 / CHUNK_SIZE;
            remnant_size = arg1 - (total_obj * CHUNK_SIZE);

            while (i < total_obj)
            {
                memset(&temp_call_stack[0], 0, sizeof(temp_call_stack));
                memset(&size[0], 0, sizeof(size));
                memset(&chunk_index[0], 0, sizeof(chunk_index));

                // fprintf(stderr, "iter:%d\n",i);
                strcat(temp_call_stack, call_stack);
                sprintf(size, ":%d", CHUNK_SIZE);
                strcat(temp_call_stack, obj_size);
                strcat(temp_call_stack, size);
                sprintf(chunk_index, ":%d", i);
                strcat(temp_call_stack, chunk_index);

                // fprintf(stderr, "original %s\n", call_stack);
                // fprintf(stderr, "adaptado %s\n", temp_call_stack);

                if (check_address(hash(temp_call_stack)))
                {
                    fprintf(stderr, "binding to dram :%d\n", hash(temp_call_stack));
                    g_nodemask = DRAM; // NUMA 1 (CPU+MEM); // NUMA 0 ??
                }
                else
                {
                    fprintf(stderr, "binding to CXL :%d\n", hash(temp_call_stack));
                    g_nodemask = CXL; // NUMA 100 = NUMA 2 ?
                }
                if (mbind((void *)*result + (i * CHUNK_SIZE), (unsigned long)CHUNK_SIZE, MPOL_BIND, &g_nodemask, 64, MPOL_MF_MOVE) == -1)
                {
                    fprintf(stderr, "Error:%d\n", errno);
                    perror("Error description");
                }
                i++;
            }
            if (remnant_size > 0)
            {
                memset(&temp_call_stack[0], 0, sizeof(temp_call_stack));
                memset(&size[0], 0, sizeof(size));
                memset(&chunk_index[0], 0, sizeof(chunk_index));

                strcat(temp_call_stack, call_stack);
                sprintf(size, ":%d", remnant_size);
                strcat(temp_call_stack, obj_size);
                strcat(temp_call_stack, size);
                sprintf(chunk_index, ":%d", i);
                strcat(temp_call_stack, chunk_index);

                if (check_address(hash(temp_call_stack)))
                {
                    fprintf(stderr, "binding to dram :%d\n", hash(temp_call_stack));
                    g_nodemask = DRAM;
                }
                else
                {
                    fprintf(stderr, "binding to CXL :%d\n", hash(temp_call_stack));
                    g_nodemask = CXL;
                }
                if (mbind((void *)*result + (i * CHUNK_SIZE), (unsigned long)remnant_size, MPOL_BIND, &g_nodemask, 64, MPOL_MF_MOVE) == -1)
                {
                    fprintf(stderr, "Error:%d\n", errno);
                    perror("Error description");
                }
            }
            else
            {
                memset(&temp_call_stack[0], 0, sizeof(temp_call_stack));
                memset(&size[0], 0, sizeof(size));
                memset(&chunk_index[0], 0, sizeof(chunk_index));

                strcat(temp_call_stack, call_stack);
                sprintf(size, ":%d", CHUNK_SIZE);
                strcat(temp_call_stack, obj_size);
                strcat(temp_call_stack, size);
                sprintf(chunk_index, ":%d", i);
                strcat(temp_call_stack, chunk_index);

                if (check_address(hash(temp_call_stack)))
                {
                    fprintf(stderr, "binding to dram :%d\n", hash(temp_call_stack));
                    g_nodemask = DRAM;
                }
                else
                {
                    fprintf(stderr, "binding to CXL :%d\n", hash(temp_call_stack));
                    g_nodemask = CXL;
                }
                if (mbind((void *)*result + (i * CHUNK_SIZE), (unsigned long)CHUNK_SIZE, MPOL_BIND, &g_nodemask, 64, MPOL_MF_MOVE) == -1)
                {
                    fprintf(stderr, "Error:%d\n", errno);
                    perror("Error description");
                }
            }
        }
        else
        { // end of test arg1 > CHUNK_SIZE
            memset(&temp_call_stack[0], 0, sizeof(temp_call_stack));
            memset(&size[0], 0, sizeof(size));
            memset(&chunk_index[0], 0, sizeof(chunk_index));

            strcat(temp_call_stack, call_stack);
            sprintf(size, ":%d", arg1);
            strcat(temp_call_stack, obj_size);
            strcat(temp_call_stack, size);
            sprintf(chunk_index, ":%d", 0);
            strcat(temp_call_stack, chunk_index);

            // fprintf(stderr, "original %s\n", call_stack);
            // fprintf(stderr, "adaptado %s\n", temp_call_stack);

            if (check_address(hash(temp_call_stack)))
            {
                fprintf(stderr, "binding to dram :%d\n", hash(temp_call_stack));
                g_nodemask = DRAM;
            }
            else
            {
                fprintf(stderr, "binding to CXL :%d\n", hash(temp_call_stack));
                g_nodemask = CXL;
            }
            if (mbind((void *)*result, (unsigned long)arg1, MPOL_BIND, &g_nodemask, 64, MPOL_MF_MOVE) == -1)
            {
                fprintf(stderr, "Error:%d\n", errno);
                perror("Error description");
            }
        }
        pthread_mutex_unlock(&g_count_mutex);
        return 0;
    }
    else if (syscall_number == SYS_munmap)
    {
        /* pass it on to the kernel */
        *result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return 0;
    }
    else
    {
        return 1;
    }
}

static __attribute__((constructor)) void
init(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0); // avoid buffer from printf
    redirect_stdout("/tmp/call_stack_bind.txt");
    read_parameters_for_binding();
    intercept_hook_point = hook;
}
