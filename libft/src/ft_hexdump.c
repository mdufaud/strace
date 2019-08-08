/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_hexdump.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/24 14:30:31 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/24 16:38:41 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	print_chars(void *mem, int begin, int end, int size)
{
	while (begin <= end)
	{
		if (begin >= size)
			ft_putchar(' ');
		else if (ft_isprint(((char *)mem)[begin]))
			ft_putchar(((char *)mem)[begin]);
		else
			ft_putchar('.');
		begin++;
	}
	ft_putchar('\n');
}

static void	print_hex(void *mem, unsigned int index)
{
	unsigned int	hex;

	hex = 0xFF & ((char *)mem)[index];
	if (hex < 16)
		ft_putchar('0');
	ft_puthex(hex);
	ft_putchar(' ');
}

static void	print_addr(unsigned int index)
{
	unsigned int	max;
	unsigned int	size;
	unsigned int	index_size;
	unsigned int	i;

	i = 0;
	max = -1;
	size = ft_numsize(max, 16);
	index_size = ft_numsize(index, 16);
	ft_putstr("0x");
	while (i < (size - index_size))
	{
		ft_putchar('0');
		i++;
	}
	ft_puthex(index);
	ft_putstr(": ");
}

void		ft_hexdump(void *mem, unsigned int size)
{
	unsigned int		i;
	unsigned int		cols;

	i = 0;
	cols = 8;
	while (i < size + (size % cols == 0 ? 0 : (cols - (size % cols))))
	{
		if ((i % cols) == 0)
			print_addr(i);
		if (i < size)
			print_hex(mem, i);
		else
			ft_putstr("   ");
		if ((i % cols) == cols - 1)
			print_chars(mem, i - (cols - 1), i, size);
		i++;
	}
}
