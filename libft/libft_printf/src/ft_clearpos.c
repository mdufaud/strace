/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_clearpos.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/19 14:46:45 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/07 21:20:57 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

void	ft_clearpos(t_ftprintf *env)
{
	env->is_hash = 0;
	env->is_0 = 0;
	env->is_plus = 0;
	env->is_less = 0;
	if (env->pos)
	{
		free(env->pos);
		env->pos = NULL;
	}
	env->is_num = 0;
	env->is_neg = 0;
	env->is_unsigned = 0;
	env->is_space = 0;
	env->size_flag = 0;
}
