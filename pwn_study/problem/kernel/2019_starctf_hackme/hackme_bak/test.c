#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

struct info{
    long index;
    long *strings;
    long length;
    long offset;
};

void delete(int fd,long index)
{
	struct info temp;
	temp.index = index;
	ioctl(fd, 0x30001, temp);
}

void edit(int fd,long index,long offset,long length,long *strings)
{
	struct info temp;
	temp.index = index;
	temp.strings = strings;
	temp.length = length;
	temp.offset = offset;
	ioctl(fd,0x30002,temp);
}

void show(int fd,long index,long offset,long length,long *strings)
{
	struct info temp;
	temp.index = index;
	temp.strings = strings;
	temp.length = length;
	temp.offset = offset;
	ioctl(fd,0x30003,temp);
}

void add(int fd,long index,long offset,long length,long *strings)
{
	struct info temp;
	temp.index = index;
	temp.strings = strings;
	temp.length = length;
	temp.offset = offset;
	ioctl(fd,0x30000,temp);
}

int main()
{
	// 打开两次设备
	int fd = open("/dev/hackme", 2);
	char buf[100] = {0};
	add(fd,0,0,0x100,"testtest");
	show(fd,0,0,0x100,buf);
	printf("%s\n",buf);
	edit(fd,0,0,0x100,"test2222");
	show(fd,0,0,0x100,buf);
	printf("%s\n",buf);
	delete(fd,0);
	return 0;
}
