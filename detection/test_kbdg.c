#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define KBDG_DEFAULT_MAJOR      252
#define KBDG_DEFAULT_MINOR      0
#define KBDG_DEFAULT_DEVICE     "/tmp/debugx"
#define KBDG_MODULE             "debug"

int main( void ) {
	struct stat sb;
	char buf[32] = {0};
	int fd;

	if ( stat(KBDG_DEFAULT_DEVICE, &sb) ) {
		mknod(KBDG_DEFAULT_DEVICE, 0666| S_IFCHR, 
				(KBDG_DEFAULT_MAJOR << 8 ) | 1 );
		if ( stat(KBDG_DEFAULT_DEVICE, &sb) ) {
			printf("Unable to stat %s\n", KBDG_DEFAULT_DEVICE);
			return(0);
		}
	}

	fd = open(KBDG_DEFAULT_DEVICE, O_RDWR );
	if ( fd == -1 ) {
		printf("Unable to open %s\n", KBDG_DEFAULT_DEVICE);
		return(0);
	}

	write( fd, buf, 32 );
	read( fd, buf, 32 );

	close( fd );

	return(0);
}
