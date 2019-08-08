/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/17 15:54:36 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:17:06 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

int				ft_printf(char *format, ...)
{
	t_ftprintf	*env;
	int			count;

	if (!(env = ft_printf_allocate(format)))
		return (-1);
	va_start(env->arg, format);
	ft_parse_printf(env);
	ft_putstr(env->buffer);
	free(env->buffer);
	va_end(env->arg);
	count = env->count;
	free(env);
	return (count);
}
