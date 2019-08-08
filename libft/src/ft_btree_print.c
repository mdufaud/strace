/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_print.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 14:37:20 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/17 15:24:55 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <unistd.h>

size_t		ft_btree_sizeint(void *item, size_t size)
{
	int		n;

	(void)size;
	n = *((int *)(item));
	return (ft_numsize(n, 10));
}

size_t		ft_btree_sizestr(void *item, size_t size)
{
	(void)item;
	return (size);
}

void		ft_btree_printint(void *item, size_t size)
{
	int		n;

	(void)size;
	n = *((int *)(item));
	ft_putnbr(n);
}

void		ft_btree_printstr(void *item, size_t size)
{
	write(1, item, size);
}
