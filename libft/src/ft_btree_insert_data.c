/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_insert_data.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 14:13:13 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/20 13:42:59 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static t_btree	*set_new(t_btree *root, t_btree *new)
{
	new->parent = root;
	return (new);
}

static void		recursive_insert(t_btree **root, t_btree *new,
												int (*cmpf)(void *, void *))
{
	if (!(*root))
	{
		*root = set_new(NULL, new);
		return ;
	}
	if (cmpf(new->item, (*root)->item) < 0)
	{
		if ((*root)->left)
			recursive_insert(&((*root)->left), new, cmpf);
		else
			(*root)->left = set_new((*root), new);
	}
	else
	{
		if ((*root)->right)
			recursive_insert(&((*root)->right), new, cmpf);
		else
			(*root)->right = set_new((*root), new);
	}
}

void			ft_btree_insert_data(t_btree **root, void *item, size_t size,
												int (*cmpf)(void *, void *))
{
	t_btree		*new;

	if (!(new = ft_btree_create_node(item, size)))
		return ;
	recursive_insert(root, new, cmpf);
	ft_btree_repare(root, new);
	while (new->parent)
		new = new->parent;
	*root = new;
}
