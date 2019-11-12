#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#define VERIFY(x, errmsg)				\
	if(!((x))){							\
		fprintf(stderr, "%s:%d>>\n\t", 	\
				__func__, __LINE__); 	\
		perror(errmsg);					\
		exit(1);						\
	}

