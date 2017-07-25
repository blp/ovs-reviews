#include <config.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
	if(access(argv[i], F_OK ) != -1) {
	    remove(argv[i]);
	} 
    }
    
    return 0;
}
