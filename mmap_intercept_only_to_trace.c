
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
#include <pthread.h>
#include <sys/resource.h>
#define _GNU_SOURCE
#define SIZE 2048               // callstack string size
#define CHUNK_SIZE 500002816UL // chunk size aligned with pages of 4096 bytes

char *g_line = NULL;
FILE *g_fp = NULL;
pthread_mutex_t g_count_mutex;

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

    g_fp = fopen("call_stack.txt", "w+");
    if (g_fp == NULL)
    {
        printf("Error when try to use fopen!!\n");
    }
}
void get_call_stack(char *call_stack)
{
    char *addr;
    char *p;
    char **strings;
    int static mmap_id = 0;
    int nptrs;
    int i;
    int k = 0;
    void *buffer[SIZE];
    ssize_t read;
    size_t len = 0;

    nptrs = backtrace(buffer, SIZE);
    backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO);
    fflush(stdout);

    const char *substring = getenv("APP");

    // while ((read = getline(&g_line, &len, g_fp)) != -1) {
    for (int callstack_line_index = 0; callstack_line_index < nptrs; callstack_line_index++)
    {
        read = getline(&g_line, &len, g_fp);
        p = strstr(g_line, substring);
        if (p)
        {
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
    }
    call_stack[k - 1] = '\0';
}

static int hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result)
{
    char size[SIZE];
    char chunk_index[3];
    char temp_call_stack[SIZE];
    char call_stack[SIZE] = "";
    int static mmap_id = 0;
    int total_obj;
    int i;
    unsigned long long remnant_size;
    struct timespec ts;

    if (syscall_number == SYS_mmap)
    {
        *result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
        pthread_mutex_lock(&g_count_mutex);
        clock_gettime(CLOCK_MONOTONIC, &ts);
        get_call_stack(call_stack);
        i = 0;
        if (arg1 > CHUNK_SIZE)
        {
            total_obj = arg1 / CHUNK_SIZE;
            remnant_size = arg1 - (total_obj * CHUNK_SIZE);
            while (i < total_obj)
            {
                memset(&temp_call_stack[0], 0, sizeof(temp_call_stack));
                memset(&size[0], 0, sizeof(size));
                memset(&chunk_index[0], 0, sizeof(chunk_index));

                strcat(temp_call_stack, call_stack);
                sprintf(size, ":%d", CHUNK_SIZE);
                strcat(temp_call_stack, size);
                sprintf(chunk_index, ":%d", i);
                strcat(temp_call_stack, chunk_index);

                fprintf(stderr, "%ld.%ld,mmap,%ld,%p,%ld,%s\n", ts.tv_sec, ts.tv_nsec, CHUNK_SIZE, (void *)*result + (i * CHUNK_SIZE), hash(temp_call_stack), temp_call_stack);
                i++;
            }
            if (remnant_size > 0)
            {
                memset(&temp_call_stack[0], 0, sizeof(temp_call_stack));
                memset(&size[0], 0, sizeof(size));
                memset(&chunk_index[0], 0, sizeof(chunk_index));

                strcat(temp_call_stack, call_stack);
                sprintf(size, ":%d", remnant_size);
                strcat(temp_call_stack, size);
                sprintf(chunk_index, ":%d", i);
                strcat(temp_call_stack, chunk_index);

                fprintf(stderr, "%ld.%ld,mmap,%ld,%p,%ld,%s\n", ts.tv_sec, ts.tv_nsec, remnant_size, (void *)*result + (i * CHUNK_SIZE), hash(temp_call_stack), temp_call_stack);
            }
            else
            {
                memset(&temp_call_stack[0], 0, sizeof(temp_call_stack));
                memset(&size[0], 0, sizeof(size));
                memset(&chunk_index[0], 0, sizeof(chunk_index));

                strcat(temp_call_stack, call_stack);
                sprintf(size, ":%d", CHUNK_SIZE);
                strcat(temp_call_stack, size);
                sprintf(chunk_index, ":%d", i);
                strcat(temp_call_stack, chunk_index);

                fprintf(stderr, "%ld.%ld,mmap,%ld,%p,%ld,%s\n", ts.tv_sec, ts.tv_nsec, CHUNK_SIZE, (void *)*result + (i * CHUNK_SIZE), hash(temp_call_stack), temp_call_stack);
            }
        } // arg1 > CHUNK_SIZE
        else
        {
            memset(&temp_call_stack[0], 0, sizeof(temp_call_stack));
            memset(&size[0], 0, sizeof(size));
            memset(&chunk_index[0], 0, sizeof(chunk_index));

            strcat(temp_call_stack, call_stack);
            sprintf(size, ":%d", arg1);
            strcat(temp_call_stack, size);
            sprintf(chunk_index, ":%d", i);
            strcat(temp_call_stack, chunk_index);

            fprintf(stderr, "%ld.%ld,mmap,%ld,%p,%ld,%s\n", ts.tv_sec, ts.tv_nsec, arg1, (void *)*result, hash(temp_call_stack), temp_call_stack);
        }

        pthread_mutex_unlock(&g_count_mutex);
        return 0;

    } // end of test syscall_number == SYS_mmap
    else if (syscall_number == SYS_munmap)
    {
        /* pass it on to the kernel */
        *result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
        clock_gettime(CLOCK_MONOTONIC, &ts);

        if (arg1 > CHUNK_SIZE)
        {
            total_obj = arg1 / CHUNK_SIZE;
            remnant_size = arg1 - (total_obj * CHUNK_SIZE);

            while (i < total_obj)
            {
                fprintf(stderr, "%ld.%ld,munmap,%p,%ld\n", ts.tv_sec, ts.tv_nsec, (void *)*result + (i * CHUNK_SIZE), CHUNK_SIZE);
                i++;
            }
            if (remnant_size > 0)
            {
                fprintf(stderr, "%ld.%ld,munmap,%p,%ld\n", ts.tv_sec, ts.tv_nsec, (void *)*result + (i * CHUNK_SIZE), remnant_size);
            }
            else
            {
                fprintf(stderr, "%ld.%ld,munmap,%p,%ld\n", ts.tv_sec, ts.tv_nsec, (void *)*result + (i * CHUNK_SIZE), CHUNK_SIZE);
            }
        }
        else
        { // end of test arg1 > CHUNK_SIZE
            fprintf(stderr, "%ld.%ld,munmap,%p,%ld\n", ts.tv_sec, ts.tv_nsec, (void *)arg0, arg1);
        }
        return 0;
    } // enf of test syscall_number == SYS_munmap
    else
    {
        return 1;
    }
}

static __attribute__((constructor)) void
init(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0); // avoid buffer from printf
    redirect_stdout("call_stack.txt");
    intercept_hook_point = hook;
}
