/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lltoa.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/07 22:33:19 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 14:37:27 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static void	ft_fillnbr(char *s, long long n, int is_neg, int size)
{
	int			i;
	int			j;
	long long	tmp;

	i = 0;
	if (is_neg)
		s[i++] = '-';
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

char		*ft_lltoa(long long n)
{
	char	*s;
	int		size;
	int		is_neg;

	if (n == -9223372036854775807 - 1)
		return (ft_strdup("–9223372036854775808"));
	is_neg = n < 0 ? 1 : 0;
	n = ABS(n);
	size = ft_numsize(n, 10);
	size = is_neg ? size + 1 : size;
	if (!(s = (char *)malloc(sizeof(char) * (size + 1))))
		return (NULL);
	ft_fillnbr(s, n, is_neg, size);
	return (s);
}
