/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_getflag.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:43:58 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

static int	check(t_ftprintf *env, int size)
{
	return ((env->size_flag & size));
}

static void	ft_getsizeflag(t_ftprintf *env, char *s)
{
	if (*s == 'h' && *(s + 1) && *(s + 1) == 'h' && !check(env, HH_VALUE))
		env->size_flag += HH_VALUE;
	else if (*s == 'h' && !check(env, H_VALUE))
		env->size_flag += H_VALUE;
	else if (*s == 'l' && *(s + 1) && *(s + 1) == 'l' && !check(env, LL_VALUE))
		env->size_flag += LL_VALUE;
	else if (*s == 'l' && !check(env, L_VALUE))
		env->size_flag += L_VALUE;
	else if (*s == 'j' && !check(env, J_VALUE))
		env->size_flag += J_VALUE;
	else if (*s == 'z' && !check(env, Z_VALUE))
		env->size_flag += Z_VALUE;
}

void		ft_getflag(t_ftprintf *env, char *s)
{
	if (*s == '#')
		env->is_hash = 1;
	else if (*s == '0')
		env->is_0 = 1;
	else if (*s == '+')
		env->is_plus = 1;
	else if (*s == '-')
		env->is_less = 1;
	else if (*s == ' ')
		env->is_space = 1;
	else
		ft_getsizeflag(env, s);
}
