/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_isbase.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2014/05/04 22:42:53 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int			ft_isbase(int n, int base)
{
	char	c;

	c = (char)n;
	c = ft_tolower(c);
	if (base > 1 && c >= '0')
	{
		if (c <= '9' && c <= ('0' + (base - 1)))
			return (1);
	}
	if (base > 10 && c >= 'a')
	{
		if (c <= 'z'
			&& c <= 'a' + ((base - 10) - 1))
			return (1);
	}
	return (0);
}
