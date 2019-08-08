/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_printf.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 14:49:32 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/17 15:33:20 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void		print_x_char(char c, int x)
{
	int		i;

	i = 0;
	while (i < x)
	{
		ft_putchar(c);
		i++;
	}
}

static void		print_btree(t_btree *root, size_t indent,
									void (*printfun)(void *, size_t),
									size_t (*lenfun)(void *, size_t))
{
	int		size;

	if (!root)
		return ;
	size = lenfun(root->item, root->size);
	if (root->left)
		print_btree(root->left, indent + 1 + size, printfun, lenfun);
	if (indent)
		print_x_char(' ', indent);
	if (root->color == b_red)
		ft_put_color(red);
	else
		ft_put_color(blue);
	printfun(root->item, root->size);
	ft_end_color();
	ft_putchar('\n');
	if (root->right)
		print_btree(root->right, indent + 1 + size, printfun, lenfun);
}

void			ft_btree_printf(t_btree *root,
									void (*printfun)(void *, size_t),
									size_t (*lenfun)(void *, size_t))
{
	ft_putcendl("Binary tree: (left is up and right is lower)", white);
	print_btree(root, 0, printfun, lenfun);
}
