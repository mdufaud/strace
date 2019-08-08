/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_predot.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/05 18:27:37 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/05 23:01:22 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

int		ft_predot(t_ftprintf *env)
{
	int		i;

	i = 0;
	while (env->pos && env->pos[i] && !ft_isdigit(env->pos[i])
			&& env->pos[i] != '.')
		i++;
	if (!env->pos || !env->pos[i] || env->pos[i] == '.')
		return (0);
	return (ft_atoi(env->pos + i));
}
