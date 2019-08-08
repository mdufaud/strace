/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ltoa_base.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 17:45:42 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 17:58:23 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static int	get_base_char(int c)
{
	if (c < 10)
		return (c + '0');
	else
		return ((c - 10) + 'a');
}

static void	ft_fillnbr(char *s, long n, int size, int base)
{
	int		i;
	int		j;
	long	tmp;

	i = size;
	while (i)
	{
		j = i - 1;
		tmp = n;
		while (j-- && tmp >= base)
			tmp = tmp / base;
		*(s) = get_base_char((tmp % base));
		i--;
		s++;
	}
	*s = '\0';
}

char		*ft_ltoa_base(long n, int base)
{
	char	*s;
	char	*ptr;
	int		is_neg;
	int		numsize;

	is_neg = 0;
	if (n < 0)
	{
		n = n * -1;
		is_neg = 1;
	}
	numsize = ft_numsize(n, base);
	if (!(ptr = (char *)malloc(numsize + 1)))
		return (NULL);
	s = ptr;
	if (is_neg)
		*(s++) = '-';
	ft_fillnbr(s, n, numsize, base);
	return (ptr);
}
