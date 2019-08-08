#include "ft_strace.h"
#include <sys/ptrace.h>
#include <errno.h>
#include "syscalls_def.h"

static unsigned long long	get_reg(struct user_regs_struct *regs, int n)
{
	if (n == 1)
		return (regs->rdi);
	else if (n == 2)
		return (regs->rsi);
	else if (n == 3)
		return (regs->rdx);
	else if (n == 4)
		return (regs->r10);
	else if (n == 5)
		return (regs->r8);
	else if (n == 6)
		return (regs->r9);
	return (-1);
}

static size_t				print_string_end(char *s)
{
	int		read;
	int		len;
	char	*tmp;

	tmp = s;
	s = ft_strreplace(s, "\n", "\\n");
	ft_bzero(tmp, BUF_SIZE);
	free(tmp);
	len = ft_strlen(s);
	if (len > 32)
		s[31] = 0;
	read = printf("%s\"%s\"%s", PRED, s, PRESET);
	if (len > 32)
		read += printf("...");
	ft_strdel(&s);
	return (read);
}

static size_t				print_string(t_trace *trace,
									struct user_regs_struct *regs, int n)
{
	char				*str;
	int					alloc;
	unsigned long		l;
	int					read;

	read = 0;
	if (!(str = ft_strnew(BUF_SIZE)))
		return (printf("\"malloc error\""));
	alloc = BUF_SIZE;
	while (1)
	{
		if ((int)(read + sizeof(l)) > alloc)
		{
			alloc *= 2;
			str = realloc(str, alloc);
		}
		l = ptrace(PTRACE_PEEKDATA, trace->child, get_reg(regs, n) + read);
		if (errno != 0)
		{
			str[read] = 0;
			break ;
		}
		ft_memcpy(str + read, &l, sizeof(l));
		if (ft_memchr(&l, 0, sizeof(l)) != NULL)
			break ;
		read += sizeof(l);
	}
	return (print_string_end(str));
}

static size_t				print_tab(t_trace *trace,
									struct user_regs_struct *regs, int n)
{
	char	**tab;
	int		i;
	int		tab_len;
	size_t	read;

	tab = (char **)(get_reg(regs, n));
	tab_len = ft_tablen(tab);
	if (tab_len > MAX_TAB)
		return (printf("%s[/* %d vars */]%s", PMAGENTA, tab_len, PRESET));
	read = printf("%s[", PMAGENTA);
	i = 0;
	(void)trace;
	while (i < tab_len)
	{
		read += printf("\"%s\"", tab[i]);
		if (i + 1 < tab_len)
			read += printf(", ");
		i++;
	}
	read += printf("]%s", PRESET);
	return (read);
}

size_t					print_arg(t_trace *trace, t_syscalls *sc,
									struct user_regs_struct *regs, int n)
{
	size_t	size;

	size = 0;
	if (sc->args_type[n] == INTEGER)
		size = printf("%s%d%s", PBLUE, (int)get_reg(regs, n + 1), PRESET);
	else if (sc->args_type[n] == STRING)
		size = print_string(trace, regs, n + 1);
	else if (sc->args_type[n] == POINTER)
		size = get_reg(regs, n + 1) ? \
			   printf("%s0x%llx%s", PYELLOW, get_reg(regs, n + 1), PRESET) :\
			   printf("%sNULL%s", PYELLOW, PRESET);
	else if (sc->args_type[n] == STRUCTURE)
		size = printf("%s{Structure}%s", PGREEN, PRESET);
	else if (sc->args_type[n] == STR_TAB)
		size = print_tab(trace, regs, n + 1);
	else if (sc->args_type[n] == VA_ARG)
		size = printf("...");
	if (n + 2 <= sc->n)
		size += printf(", ");
	return (size);
}
