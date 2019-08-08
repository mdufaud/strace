#include "ft_strace.h"
#include <sys/time.h>

void		sort_stat_time(t_trace *trace)
{
	t_callstat	tmp;
	int			i;
	int			j;

	i = 0;
	while (i < N_SYSCALLS)
	{
		j = i + 1;
		while (j < N_SYSCALLS)
		{
			if (timercmp(&trace->stat.call[i].time, &trace->stat.call[j].time, <))
			{
				tmp = trace->stat.call[i];
				trace->stat.call[i] = trace->stat.call[j];
				trace->stat.call[j] = tmp;
			}
			j++;
		}
		i++;
	}
}

void		sort_stat_call(t_trace *trace)
{
	t_callstat	tmp;
	int			i;
	int			j;

	i = 0;
	while (i < N_SYSCALLS)
	{
		j = i + 1;
		while (j < N_SYSCALLS)
		{
			if (trace->stat.call[i].call < trace->stat.call[j].call)
			{
				tmp = trace->stat.call[i];
				trace->stat.call[i] = trace->stat.call[j];
				trace->stat.call[j] = tmp;
			}
			j++;
		}
		i++;
	}
}

void		sort_stat_err(t_trace *trace)
{
	t_callstat	tmp;
	int			i;
	int			j;

	i = 0;
	while (i < N_SYSCALLS)
	{
		j = i + 1;
		while (j < N_SYSCALLS)
		{
			if (trace->stat.call[i].err < trace->stat.call[j].err)
			{
				tmp = trace->stat.call[i];
				trace->stat.call[i] = trace->stat.call[j];
				trace->stat.call[j] = tmp;
			}
			j++;
		}
		i++;
	}
}
