/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_postdot.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/05 17:21:50 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/05 19:31:46 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

int		ft_postdot(t_ftprintf *env)
{
	int		i;
	int		ret;

	i = 0;
	ret = 0;
	while (env->pos && env->pos[i] && env->pos[i] != '.')
		i++;
	if (env->pos && env->pos[i] == '.')
	{
		i++;
		ret = ft_atoi(env->pos + i);
	}
	return (ret);
}
