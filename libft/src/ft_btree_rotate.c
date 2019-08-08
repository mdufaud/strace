/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_rotate.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 17:50:28 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 13:13:53 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void			ft_btree_rotate_left(t_btree **root, t_btree *node)
{
	t_btree		*new;

	if (!node || !(new = node->right))
		return ;
	node->right = new->left;
	if (node->right)
		node->right->parent = node;
	new->parent = node->parent;
	if (!node->parent)
		*root = new;
	else if (node == node->parent->left)
		node->parent->left = new;
	else
		node->parent->right = new;
	new->left = node;
	node->parent = new;
}

void			ft_btree_rotate_right(t_btree **root, t_btree *node)
{
	t_btree		*new;

	if (!node || !(new = node->left))
		return ;
	node->left = new->right;
	if (node->left)
		node->left->parent = new;
	new->parent = node->parent;
	if (!node->parent)
		*root = new;
	else if (node == node->parent->left)
		node->parent->left = new;
	else
		node->parent->right = new;
	new->right = node;
	node->parent = new;
}
