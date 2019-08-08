#include "ft_strace.h"
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "syscalls_def.h"
#include <errno.h>
#include <sys/time.h>

static int	check_status(t_trace *trace, int status)
{
	int						code;

	if (WIFEXITED(status))
	{
		code = WEXITSTATUS(status);
		trace->has_exit = 1;
		trace->exit_code = code;
		return (1);
	}
	if (WIFSIGNALED(status))
	{
		if (!trace->interactive)
			print_stat(trace);
		fflush(stdout);
		if (WTERMSIG(status) == SIGKILL)
			ft_printf("\n");
		ft_printf("+++ killed by %s %s+++\n",
				get_signame(WTERMSIG(status)),
				WCOREDUMP(status) ? "(core dumped) " : "");
		trace->exit_code = status;
		kill(getpid(), WTERMSIG(status));
		return (1);
	}
	return (0);
}

static int	next_syscall(t_trace *trace)
{
	int						status;

	while (1)
	{
		if (ptrace(PTRACE_SYSCALL, trace->child, NULL, trace->sig) < 0)
			error("ptrace could not get syscall");
		remove_sig();
		wait4(trace->child, &status, __WALL, NULL);
		add_sig();
		trace->sig = 0;
		if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
			return (0);
		else if (trace->stat.n_calls > 0)
			print_siginfo(trace);
		if (check_status(trace, status))
			return (1);
	}
	return (0);
}

static int	trace_syscall_ret(t_trace *trace, timeval_t *time)
{
	struct user_regs_struct	regs;

	if (next_syscall(trace))
		return (1);
	if (ptrace(PTRACE_GETREGS, trace->child, NULL, &regs) < 0)
		error("ptrace could not get regs");
	add_stat_ret(trace, &regs, time);
	print_syscall_ret(trace, &regs);
	trace->stat.n_calls++;
	return (0);
}

static int	trace_seized_child(t_trace *trace)
{
	struct user_regs_struct	regs;
	timeval_t				time;

	ptrace(PTRACE_SETOPTIONS, trace->child, 0,
			PTRACE_O_TRACESYSGOOD);
	trace->stat.n_calls = 0;
	while (1)
	{
		if (next_syscall(trace))
			break ;
		gettimeofday(&time, NULL);
		if (ptrace(PTRACE_GETREGS, trace->child, NULL, &regs) < 0)
			error("ptrace could not get regs");
		if (!trace->stat.n_calls && regs.orig_rax == KILL)
			continue ;
		add_stat(trace, &regs);
		print_syscall(trace, &regs);
		if (trace_syscall_ret(trace, &time))
			break ;
	}
	if (trace->has_exit && trace->interactive)
		printf("+++ exited with %d +++\n", trace->exit_code);
	else if (!trace->interactive)
		print_stat(trace);
	ptrace(PTRACE_DETACH, trace->child, NULL, NULL);
	return (trace->exit_code);
}

int			strace(t_trace *trace)
{
	pid_t				child;
	int					status;

	if ((child = fork()) == 0)
	{
		if (execve(trace->prog, trace->args, trace->env) < 0)
			error(ft_strjoin("exec: ", strerror(errno)));
		exit(1);
	}
	else if (child > 0)
	{
		add_sig_handler();
		trace->child = child;
		if ((ptrace(PTRACE_SEIZE, child, NULL, NULL)) < 0)
			error("ptrace seize failed");
		if ((ptrace(PTRACE_INTERRUPT, child, NULL, NULL)) < 0)
			error("ptrace interrupt failed");
		remove_sig();
		waitpid(trace->child, &status, __WALL);
		add_sig();
		trace->sig = 0;
		return (trace_seized_child(trace));
	}
	else
		return (ierror("Fork failed"));
}
