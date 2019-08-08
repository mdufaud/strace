/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_repare.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 17:48:54 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 12:47:12 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void		btree_repare_case_1(t_btree *node)
{
	node->color = b_black;
}

static void		btree_repare_case_3(t_btree **root, t_btree *node)
{
	t_btree		*gp;
	t_btree		*uncle;

	uncle = ft_btree_uncle(node);
	gp = node->parent ? node->parent->parent : NULL;
	if (node->parent)
		node->parent->color = b_black;
	if (uncle)
		uncle->color = b_black;
	if (gp)
	{
		gp->color = b_red;
		ft_btree_repare(root, gp);
	}
}

static void		btree_repare_case_4(t_btree **root, t_btree *node)
{
	t_btree		*gp;

	gp = node->parent ? node->parent->parent : NULL;
	if (gp && gp->left && node == gp->left->right)
	{
		ft_btree_rotate_left(root, node->parent);
		node = node->left;
	}
	else if (gp && gp->right && node == gp->right->left)
	{
		ft_btree_rotate_right(root, node->parent);
		node = node->right;
	}
	gp = node->parent ? node->parent->parent : NULL;
	if (node->parent && node == node->parent->left)
		ft_btree_rotate_right(root, gp);
	else
		ft_btree_rotate_left(root, gp);
	if (gp)
		gp->color = b_red;
	if (node->parent)
		node->parent->color = b_black;
}

void			ft_btree_repare(t_btree **root, t_btree *node)
{
	t_btree		*uncle;

	uncle = ft_btree_uncle(node);
	if (!node->parent)
		btree_repare_case_1(node);
	else if (node->parent->color == b_black)
		return ;
	else if (uncle && uncle->color == b_red)
		btree_repare_case_3(root, node);
	else
		btree_repare_case_4(root, node);
}
