#include <stdio.h>
#include <unistd.h>

int main( void ) {
	char *argv[2] = { "/usr/bin/uptime", NULL };

	execve(argv[0], argv, NULL);
	return(0);
}
