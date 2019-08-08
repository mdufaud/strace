/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printfchar.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/19 14:46:45 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/07 16:39:01 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

char	*ftprintf_char(t_ftprintf *env)
{
	char	c;
	char	*s;

	c = 0;
	c = (char)va_arg(env->arg, int);
	s = ft_strnew(1);
	s[0] = c;
	s[1] = 0;
	ft_padding(env, &s);
	return (s);
}
