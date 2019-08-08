/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_puthex.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/24 15:43:04 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>

static void	ft_printhex(unsigned int n)
{
	char	c;

	if (n >= 10)
		c = n + 87;
	else
		c = n + 48;
	write(1, &c, 1);
}

void		ft_puthex(unsigned int n)
{
	if (n < 16)
		ft_printhex(n);
	else
	{
		ft_puthex(n / 16);
		ft_printhex(n % 16);
	}
}
