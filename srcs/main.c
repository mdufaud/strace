#include "ft_strace.h"
#include <unistd.h>
#include <stdlib.h>

static int	prog_error(char *file)
{
	ft_fprintf(2, "ft_strace: Can't access '%s': "
			"No such file or directory\n", file);
	return (1);
}

static int	set_prog_name(t_trace *trace, char *arg)
{
	if (arg[0] == '/')
	{
		trace->prog = ft_strdup(arg);
		return (0);
	}
	else if (access(arg, F_OK))
	{
		if (!(trace->prog = get_bin_from_path(arg, trace)))
			return (prog_error(arg));
	}
	else
		trace->prog = ft_strdup(arg);
	return (0);
}

size_t				print_string_end(char *s)
{
	int		read;
	int		len;
	int		endl;

	len = ft_strlen(s);
	endl = 0;
	if (len > 0)
		endl = s[len - 1] == '\n' ? 1 : 0;
	if (endl)
		s[len] = 0;
	if (len > (32 - endl))
		s[31 - endl] = 0;
	read = printf("\"%s\"", s);
	if (endl)
		read += printf("\\n");
	if (len > (32 - endl))
		read += printf("...");
	return (read);
}


static int	get_args(t_trace *trace, int argc, char **argv)
{
	int		i;

	i = 1;
	while (i < argc)
	{
		if (argv[i][0] == '-')
		{
			if (ft_strchr(argv[i], 'c'))
				trace->interactive = 0;
			if (ft_strchr(argv[i], 'e'))
				trace->sort = SORT_ERR;
			if (ft_strchr(argv[i], 'n'))
				trace->sort = SORT_CALL;
			i++;
		}
		else
			break ;
	}
	if (i == argc)
		return (ft_fprintf(2, "ft_strace: usage "
					"./ft_strace [-c/e/n] <binary> [arguments]\n") % 1 + 1);
	if (set_prog_name(trace, argv[i]))
		return (1);
	trace->args = ft_tabdup(argv + i);
	return (0);
}

int			main(int argc, char **argv, char **env)
{
	t_trace		trace;

	if (argc <= 1)
		return (ft_fprintf(2, "ft_strace: usage "
					"./ft_strace [-c/e/n] <binary> [arguments]\n") % 1 + 1);
	trace.interactive = 1;
	get_trace(&trace);
	trace.env = env;
	trace.sort = SORT_TIME;
	trace.errno = get_errno();
	trace.ker_errno = get_ker_errno();
	trace.prog = NULL;
	if (get_args(&trace, argc, argv))
		return (1);
	if (!(trace.syscalls = prepare_syscalls()))
		error("Could not prepare syscalls");
	trace.exit_code = 0;
	trace.has_exit = 0;
	if (!init_stat(&trace))
		error("Could not prepare stats");
	return (strace(&trace));
}
