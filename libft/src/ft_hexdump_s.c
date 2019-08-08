/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_hexdump_s.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/24 15:17:50 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/27 18:43:28 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static char	*print_chars(void *mem, int begin, int end, int size)
{
	char	*s;

	if (!(s = ft_strnew(end - begin + 2)))
		return (NULL);
	while (begin <= end)
	{
		if (begin >= size)
			ft_strcat(s, " ");
		else if (ft_isprint(((char *)mem)[begin]))
			ft_strncat(s, ((char *)mem) + begin, 1);
		else
			ft_strcat(s, ".");
		begin++;
	}
	ft_strcat(s, "\n");
	return (s);
}

static void	print_hex(char *s, void *mem, unsigned int index)
{
	unsigned int	hex;
	char			*tmp;

	hex = 0xFF & ((char *)mem)[index];
	if (hex < 16)
		ft_strcat(s, "0");
	tmp = ft_ultoa_base(hex, 16);
	ft_strcat(s, tmp);
	free(tmp);
	ft_strcat(s, " ");
}

static void	print_addr(char *s, unsigned int index)
{
	unsigned int	index_size;
	unsigned int	i;
	char			*tmp;

	i = 0;
	index_size = ft_numsize(index, 16);
	ft_strcat(s, "0x");
	while (i < (8 - index_size))
	{
		ft_strcat(s, "0");
		i++;
	}
	tmp = ft_ultoa_base(index, 16);
	ft_strcat(s, tmp);
	free(tmp);
	ft_strcat(s, ": ");
}

static char	*calc_size(unsigned int cols, unsigned int size)
{
	char			*s;
	unsigned int	total;
	unsigned int	n_lines;

	n_lines = size + (size % cols == 0 ? 0 : (cols - (size % cols)));
	n_lines = (n_lines / cols) + 1;
	total = ((2 + cols) + 3 + (cols * 3) + cols) * n_lines;
	if (!(s = ft_strnew(total)))
		return (NULL);
	return (s);
}

char		*ft_hexdump_s(void *mem, unsigned int size)
{
	unsigned int		i;
	unsigned int		cols;
	char				*s;
	char				*tmp;

	i = 0;
	cols = 8;
	s = calc_size(cols, size);
	while (s && i < size + (size % cols == 0 ? 0 : (cols - (size % cols))))
	{
		if ((i % cols) == 0)
			print_addr(s, i);
		if (i < size)
			print_hex(s, mem, i);
		else
			ft_strcat(s, "   ");
		if ((i % cols) == cols - 1 &&
				(tmp = print_chars(mem, i - (cols - 1), i, size)))
		{
			s = ft_strcat(s, tmp);
			free(tmp);
		}
		i++;
	}
	return (s);
}
