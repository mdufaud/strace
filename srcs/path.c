#include "ft_strace.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static char	*get_binary(char *path, char *proj)
{
	char	**split;
	char	*tmp;
	char	*ret;
	int		i;

	i = 0;
	if (!(split = ft_strsplit(ft_strchr(path, '/'), ':')))
		return (NULL);
	tmp = NULL;
	ret = NULL;
	while (split[i])
	{
		tmp = ft_strtjoin(split[i], "/", proj);
		if (!access(tmp, F_OK))
		{
			ret = tmp;
			break ;
		}
		free(tmp);
		i++;
	}
	ft_tabfree(&split);
	return (ret);
}

char		*get_bin_from_path(char *proj, t_trace *trace)
{
	int		i;

	i = 0;
	while (trace->env[i])
	{
		if (!ft_strncmp(trace->env[i], "PATH=", sizeof("PATH")))
			return (get_binary(trace->env[i], proj));
		i++;
	}
	error("Could not get PATH");
	return (NULL);
}

