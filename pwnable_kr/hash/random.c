#include <stdio.h>
#include <stdlib.h>
typedef unsigned int DWORD;
int random_(){
        return (DWORD)rand();
}
int main(int argc, char **argv){
        int n=10,i,number,info;
	int rands[8];
	scanf("%d",&n);
        scanf("%d",&number);
	scanf("%d",&info);
	srand(n);
        for (int i = 0; i <= number; i++) rands[i] = rand();
    	info -= rands[1] + rands[2] - rands[3] + rands[4] + rands[5] - rands[6] + rands[7];
        printf("%x\n", info);
        return 0;
}
