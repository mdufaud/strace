/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoui.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/07 18:30:19 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/07 18:34:03 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

unsigned int	ft_atoui(const char *str)
{
	int				is_ng;
	unsigned int	val;

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
