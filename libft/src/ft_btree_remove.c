/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_remove.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/17 16:22:32 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 19:05:10 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static void		replace_node(t_btree **root, t_btree *node, t_btree *new)
{
	if (node->parent && node->parent->left == node)
		node->parent->left = new;
	else if (node->parent && node->parent->right == node)
		node->parent->right = new;
	if (node == *root)
		*root = new;
	if (!new)
		return ;
	if (node->left)
		node->left->parent = new;
	if (node->right)
		node->right->parent = new;
	if (new->left && new->parent)
		new->parent->left = new->left;
	if (new->right && new->parent)
		new->parent->right = new->right;
	if (new->parent && new->parent->left == new)
		new->parent->left = NULL;
	else if (new->parent && new->parent->right == new)
		new->parent->right = NULL;
	new->parent = node->parent;
	new->left = node->left == new ? new->left : node->left;
	new->right = node->right == new ? new->right : node->right;
}

void			ft_btree_remove(t_btree **root, void *data,
								int (*cmpf)(void *, void *),
								void (*freefun)(void *, size_t))
{
	t_btree		*node;
	t_btree		*child;

	if (!(node = ft_btree_search_node(*root, data, cmpf)))
		return ;
	child = ft_btree_search_max_node(node->left);
	if (!child)
		child = ft_btree_search_min_node(node->right);
	replace_node(root, node, child);
	if (child)
		ft_btree_repare(root, child);
	freefun(node->item, node->size);
	free(node);
}
