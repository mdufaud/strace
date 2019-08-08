#include "ft_strace.h"
#include <sys/ptrace.h>
#include <sys/time.h>

static void	add_total(t_callstat stat, int *call, int *err, timeval_t *time)
{
	if (stat.call && (stat.time.tv_sec || stat.time.tv_usec))
	{
		*err = *err + stat.err;
		*call = *call + stat.call;
		tv_add(time, time, &stat.time);
	}
}

static void	print_syscall_stat(t_callstat stat, float total)
{
	timeval_t	div;
	float		percentage;
	float		seconds;

	if (!stat.call || !(stat.time.tv_sec || stat.time.tv_usec))
		return ;
	seconds = tv_float(&stat.time);
	percentage = seconds * 100.0;
	if (percentage != 0.0)
		percentage = percentage / total;
	ft_bzero(&div, sizeof(timeval_t));
	tv_div(&div, &stat.time, stat.call);
	printf("%6.2f", percentage);
	printf("%12.6f", seconds);
	printf("%12lu", (long)(1000000 * div.tv_sec + div.tv_usec));
	printf("%9u", stat.call);
	if (stat.err)
		printf("%s%11u%s ", PRED, stat.err, PRESET);
	else
		printf("%11s ", " ");
	printf("%s%s%s\n", PCYAN, stat.name, PRESET);
}

static void	print_start_or_end(int start, float time, unsigned int total,
																char *err)
{
	if (start)
	{
		printf("%s%6.6s %11.11s %11.11s %9.9s %9.9s %s%s\n",
				PGREEN,
				"% time", "seconds", "usecs/call", "calls", "errors", "syscall",
				PRESET);
		printf("%s%6.6s %11.11s %11.11s %9.9s %9.9s %s%s\n",
				PYELLOW,
				DASHES, DASHES, DASHES, DASHES, DASHES, DASHES,
				PRESET);
		return ;
	}
	printf("%s%6.6s %11.11s %11.11s %9.9s %9.9s %s%s\n",
			PYELLOW,
			DASHES, DASHES, DASHES, DASHES, DASHES, DASHES,
			PRESET);
	printf("%s%s %11.6f %10.11s %9u %s%10.9s%s %s%s\n",
			PGREEN,
			"100.00", time, "", total, PRED, err, PGREEN, "total",
			PRESET);
	free(err);
}

static void	good_sort(t_trace *trace)
{
	if (trace->sort == SORT_CALL)
		sort_stat_call(trace);
	else if (trace->sort == SORT_ERR)
		sort_stat_err(trace);
	else
		sort_stat_time(trace);
}

void		print_stat(t_trace *trace)
{
	int			i;
	int			t_call;
	int			t_err;
	timeval_t	t_time;

	t_call = 0;
	t_err = 0;
	print_start_or_end(1, 0.0, 0, NULL);
	ft_bzero(&t_time, sizeof(timeval_t));
	good_sort(trace);
	i = 0;
	while (i < N_SYSCALLS)
	{
		add_total(trace->stat.call[i], &t_call, &t_err, &t_time);
		i++;
	}
	i = 0;
	while (i < N_SYSCALLS)
	{
		print_syscall_stat(trace->stat.call[i], tv_float(&t_time));
		i++;
	}
	print_start_or_end(0, tv_float(&t_time), t_call, ft_itoa(t_err));
	ptrace(PTRACE_DETACH, trace->child, NULL, NULL);
	exit(0);
}
