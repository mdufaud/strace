/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ulltoa.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 14:37:21 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static void	ft_fillnbr(char *s, unsigned long long n, int size)
{
	int					i;
	int					j;
	unsigned long long	tmp;

	i = 0;
	while (i < size)
	{
		j = (size - i) - 1;
		tmp = n;
		while (j-- && tmp >= 10)
			tmp = tmp / 10;
		s[i] = (tmp % 10) + 48;
		i++;
	}
	s[i] = 0;
}

char		*ft_ulltoa(unsigned long long n)
{
	char	*s;
	int		size;

	size = ft_numsize(n, 10);
	if (!(s = (char *)malloc(sizeof(char) * (size + 1))))
		return (NULL);
	ft_fillnbr(s, n, size);
	return (s);
}
