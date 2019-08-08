#ifndef FT_STRACE_H
# define FT_STRACE_H

# include "libft.h"
# include "libftprintf.h"
# include <stdio.h>
# include <sys/user.h>
# include <sys/time.h>
# include <time.h>

# ifdef __x86_64__
#  define SC_RETCODE	(8 * regs->rax)
# else
#  define SC_RETCODE	(4 * regs->eax)
# endif

# define INTEGER		0
# define STRING			1
# define POINTER		2
# define STRUCTURE		3
# define STR_TAB		4
# define VOID			5
# define VA_ARG			6

# define MAX_TAB		5

# define N_SYSCALLS		314

# define BUF_SIZE 		4096

# define PRESET			"\x1B[0m"
# define PRED			"\x1B[31m"
# define PGREEN			"\x1B[32m"
# define PYELLOW		"\x1B[33m"
# define PBLUE			"\x1B[34m"
# define PMAGENTA		"\x1B[35m"
# define PCYAN			"\x1B[36m"
# define PWHITE			"\x1B[37m"

# define SORT_TIME		(2 << 0)
# define SORT_CALL		(2 << 1)
# define SORT_ERR		(2 << 2)

# define DASHES			"----------------"

typedef struct			timeval	timeval_t;

typedef struct			s_syscalls
{
	int					n;
	int					*args_type;
	char				*str;
}						t_syscalls;

typedef struct			s_errno
{
	char				*name;
	char				*str;
}						t_errno;

typedef struct			s_callstat
{
	char				*name;
	unsigned int		err;
	unsigned int		call;
	struct timeval		time;
}						t_callstat;

typedef struct			s_stat
{
	unsigned int		n_calls;
	t_callstat			*call;
}						t_stat;

typedef struct			s_trace
{
	int					has_exit;
	int					exit_code;
	int					sig;
	int					interactive;
	int					sort;
	char				*prog;
	char				**args;
	char				**env;
	const t_errno		*errno;
	const t_errno		*ker_errno;
	t_stat				stat;
	pid_t				child;
	t_syscalls			**syscalls;
}						t_trace;

int						strace(t_trace *trace);
t_syscalls				**prepare_syscalls(void);
int						ierror(char *s);
void					error(char *s);
void					check_errno(char *s);
void					print_syscall(t_trace *trace,
									struct user_regs_struct *regs);
void					print_syscall_ret(t_trace *trace,
									struct user_regs_struct *regs);
char					*get_bin_from_path(char *proj, t_trace *trace);
size_t					print_arg(t_trace *trace, t_syscalls *sc,
									struct user_regs_struct *regs, int n);
void					add_sig(void);
void					print_siginfo(t_trace *trace);
char					*get_signame(int sig);
const t_errno			*get_errno(void);
const t_errno			*get_ker_errno(void);
t_trace					*get_trace(t_trace *trace);
void					remove_sig(void);
void					add_sig_handler(void);

void					tv_add(struct timeval *tv, const struct timeval *a,
													const struct timeval *b);
void					tv_div(struct timeval *tv, const struct timeval *a,
																	int n);
double					tv_float(const struct timeval *tv);
void					tv_sub(struct timeval *tv, const struct timeval *a,
													const struct timeval *b);

int						init_stat(t_trace *trace);
void					add_stat(t_trace *trace,
									struct user_regs_struct *regs);
void					add_stat_ret(t_trace *trace,
										struct user_regs_struct *regs,
										timeval_t *before);
void					print_stat(t_trace *trace);
void					sort_stat_time(t_trace *trace);
void					sort_stat_call(t_trace *trace);
void					sort_stat_err(t_trace *trace);
int						check_file(char *path);

#endif
