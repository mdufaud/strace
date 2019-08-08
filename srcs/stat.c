#include "ft_strace.h"
#include <sys/time.h>

int		init_stat(t_trace *trace)
{
	int		i;

	i = 0;
	if (!(trace->stat.call = ft_memalloc(sizeof(t_callstat) * N_SYSCALLS)))
		return (0);
	while (i < N_SYSCALLS)
	{
		ft_bzero(&trace->stat.call[i], sizeof(t_callstat));
		i++;
	}
	return (1);
}

void	add_stat(t_trace *trace, struct user_regs_struct *regs)
{
	if ((long)regs->orig_rax < 0 || (long)regs->orig_rax > N_SYSCALLS)
		return ;
	trace->stat.call[regs->orig_rax].call += 1;
	trace->stat.call[regs->orig_rax].name = trace->syscalls[regs->orig_rax]->str;
}

void	add_stat_ret(t_trace *trace, struct user_regs_struct *regs,
		timeval_t *before)
{
	timeval_t	ret;
	timeval_t	after;

	if ((long)regs->orig_rax < 0 || (int)regs->orig_rax > N_SYSCALLS)
		return ;
	if (((long)regs->rax) < 0)
		trace->stat.call[regs->orig_rax].err += 1;
	gettimeofday(&after, NULL);
	tv_sub(&ret, &after, before);
	tv_add(&trace->stat.call[regs->orig_rax].time,
			&trace->stat.call[regs->orig_rax].time, &ret);
}
