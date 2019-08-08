/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printfint.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/19 14:46:45 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/07 22:46:42 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

char				*ftprintf_int(t_ftprintf *env)
{
	long long	num;
	char		*s;

	s = NULL;
	num = ft_getarg(env);
	if (num < 0)
		env->is_neg = 1;
	s = ft_lltoa(num);
	env->is_num = 1;
	ft_padding(env, &s);
	return (s);
}
