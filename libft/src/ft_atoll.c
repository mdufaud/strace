/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoll.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/07 22:47:22 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/07 22:48:03 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

long long		ft_atoll(const char *str)
{
	int			is_ng;
	long long	val;

	val = 0;
	is_ng = 0;
	while (*str && ft_isspace(*str))
		str++;
	if (*str && (*str == '-' || *str == '+'))
	{
		if (*str == '-')
			is_ng = 1;
		str++;
	}
	while (*str && ft_isdigit(*str))
	{
		val = (val * 10) + (*str - 48) % 10;
		str++;
	}
	if (is_ng)
		val = val * -1;
	return (val);
}
