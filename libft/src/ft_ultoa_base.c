/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ultoa_base.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 17:52:11 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/27 18:28:11 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static size_t	ft_numsize_unsigned(unsigned long num, unsigned int base)
{
	int	i;

	i = 0;
	while (num >= base)
	{
		num = num / base;
		i++;
	}
	return (i + 1);
}

static int		get_base_char(int c)
{
	if (c < 10)
		return (c + '0');
	else
		return ((c - 10) + 'a');
}

static void		ft_fillnbr(char *s, unsigned long n, int size, int base)
{
	long			i;
	long			j;
	unsigned long	tmp;

	i = size;
	while (i)
	{
		j = i - 1;
		tmp = n;
		while (j-- && tmp >= (unsigned int)base)
			tmp = tmp / base;
		*(s) = get_base_char((tmp % base));
		i--;
		s++;
	}
	*s = '\0';
}

char			*ft_ultoa_base(unsigned long n, int base)
{
	char	*s;
	char	*ptr;
	int		numsize;

	numsize = ft_numsize_unsigned(n, base);
	if (!(ptr = (char *)ft_strnew(numsize)))
		return (NULL);
	s = ptr;
	ft_fillnbr(s, n, numsize, base);
	return (ptr);
}
