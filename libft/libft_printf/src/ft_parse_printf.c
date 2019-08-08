/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_parse_printf.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 16:09:37 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:11:26 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

static void	printf_increment(t_ftprintf *env)
{
	env->count++;
	env->i++;
}

void		ft_parse_printf(t_ftprintf *env)
{
	while (env->s[env->i])
	{
		if (env->s[env->i] == '%')
		{
			if (!printf_arg(env))
				printf_increment(env);
			else
				ft_clearpos(env);
		}
		else
			printf_increment(env);
	}
	ft_printuntil(env);
}
