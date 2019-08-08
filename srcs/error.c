#include "ft_strace.h"
#include <errno.h>

int		ierror(char *s)
{
	ft_fprintf(2, "ft_strace: error: %s\n", s);
	return (1);
}

void	error(char *s)
{
	ft_fprintf(2, "ft_strace: error: %s\n", s);
	exit(1);
}

void	check_errno(char *s)
{
	if (errno == ESRCH)
	{
		fflush(stdout);
		ft_fprintf(2, "\n%s\n", s);
		exit(1);
	}
}
