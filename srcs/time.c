#include "ft_strace.h"

void	tv_add(struct timeval *tv, const struct timeval *a, const struct timeval *b)
{
	tv->tv_sec = a->tv_sec + b->tv_sec;
	tv->tv_usec = a->tv_usec + b->tv_usec;
	if (tv->tv_usec >= 1000000)
	{
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
	}
}

void	tv_div(struct timeval *tv, const struct timeval *a, int n)
{
	tv->tv_usec = (a->tv_sec % n * 1000000 + a->tv_usec + n / 2) / n;
	tv->tv_sec = a->tv_sec / n + tv->tv_usec / 1000000;
	tv->tv_usec %= 1000000;
}

double	tv_float(const struct timeval *tv)
{
	return (tv->tv_sec + tv->tv_usec / 1000000.0);
}

void	tv_sub(struct timeval *tv, const struct timeval *a, const struct timeval *b)
{
	tv->tv_sec = a->tv_sec - b->tv_sec;
	tv->tv_usec = a->tv_usec - b->tv_usec;
	if (((long) tv->tv_usec) < 0)
	{
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	}
}
