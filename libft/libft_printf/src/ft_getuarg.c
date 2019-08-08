/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_getuarg.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2014/05/04 22:42:53 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

unsigned long long	ft_getuarg(t_ftprintf *env)
{
	if (env->size_flag & HH_VALUE)
		return ((unsigned char)va_arg(env->arg, int));
	else if (env->size_flag & H_VALUE)
		return ((unsigned short int)va_arg(env->arg, int));
	else if (env->size_flag & LL_VALUE)
		return (va_arg(env->arg, unsigned long long int));
	else if (env->size_flag & L_VALUE)
		return (va_arg(env->arg, unsigned long int));
	else if (env->size_flag & J_VALUE)
		return (va_arg(env->arg, uintmax_t));
	else if (env->size_flag & Z_VALUE)
		return (va_arg(env->arg, size_t));
	return (va_arg(env->arg, unsigned int));
}
