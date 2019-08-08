/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_search_node.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/20 16:52:27 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/20 17:55:31 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_btree		*ft_btree_search_node(t_btree *root, void *data_ref,
											int (*cmpf)(void *, void *))
{
	t_btree	*ret;

	if (!root)
		return (NULL);
	ret = NULL;
	if (!cmpf(root->item, data_ref))
		ret = root;
	if (!ret && root->left)
		ret = ft_btree_search_node(root->left, data_ref, cmpf);
	if (!ret && root->right)
		ret = ft_btree_search_node(root->right, data_ref, cmpf);
	return (ret);
}

t_btree		*ft_btree_search_max_node(t_btree *root)
{
	if (!root)
		return (NULL);
	while (root && root->right)
		root = root->right;
	return (root->left ? root->left : root);
}

t_btree		*ft_btree_search_min_node(t_btree *root)
{
	if (!root)
		return (NULL);
	while (root && root->left)
		root = root->left;
	return (root->right ? root->right : root);
}
