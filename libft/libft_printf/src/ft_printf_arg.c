/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_arg.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 15:25:01 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/23 17:37:59 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

static const t_printf_match	g_match[] = {
	{"d", &ftprintf_int},
	{"ld", &ftprintf_long},
	{"c", &ftprintf_char},
	{"s", &ftprintf_str},
	{"u", &ftprintf_uint},
	{"x", &ftprintf_hex},
	{"b", &ftprintf_bin},
	{"o", &ftprintf_oct},
	{"p", &ftprintf_addr},
	{"X", &ftprintf_upperhex},
	{NULL, NULL}
};

static int	get_pos(t_ftprintf *env)
{
	int	start;
	int	end;

	start = env->i + 1;
	end = start;
	while (env->s[end] && ft_isflag(env->s[end]))
	{
		ft_getflag(env, env->s + end);
		end++;
	}
	while (env->s[end] && (ft_isdigit(env->s[end])
				|| env->s[end] == '.'))
		end++;
	if (end > start)
		env->pos = ft_strsubi(env->s, start, end);
	return (end);
}

static void	set_arg(t_ftprintf *env, char *arg)
{
	int		arg_size;

	arg_size = ft_strlen(arg);
	if (env->pos)
		arg_size += ft_strlen(env->pos) + 1;
	else
		arg_size += 1;
	env->w += arg_size;
	env->i += arg_size;
}

static void	buffer_arg(t_ftprintf *env, char *s)
{
	if (!env->buffer)
		env->buffer = s;
	else
	{
		env->buffer = ft_strjoin_free(&env->buffer, s);
		free(s);
	}
}

int			printf_arg(t_ftprintf *env)
{
	int		i;
	int		arg_pos;
	char	*s;

	i = 0;
	arg_pos = get_pos(env);
	while (g_match[i].arg)
	{
		if (ft_strnequ((env->s + arg_pos),
					g_match[i].arg, ft_strlen(g_match[i].arg)))
		{
			ft_printuntil(env);
			set_arg(env, g_match[i].arg);
			s = g_match[i].f(env);
			buffer_arg(env, s);
			return (1);
		}
		i++;
	}
	ft_clearpos(env);
	return (0);
}
