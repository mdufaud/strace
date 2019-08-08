/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printfbin.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/26 14:21:03 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 18:18:09 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

char				*ftprintf_bin(t_ftprintf *env)
{
	unsigned long	num;
	char			*s;

	s = NULL;
	num = va_arg(env->arg, unsigned long);
	s = ft_ultoa_base(num, 2);
	env->is_num = 1;
	ft_padding(env, &s);
	return (s);
}
