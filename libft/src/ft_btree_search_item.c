/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_search_item.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 15:58:25 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/17 17:35:38 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_btree_search_item(t_btree *root, void *data_ref,
		int (*cmpf)(void *, void *))
{
	void	*item;

	if (!root)
		return (NULL);
	item = NULL;
	if (root->left)
		item = ft_btree_search_item(root->left, data_ref, cmpf);
	if (!item && !cmpf(root->item, data_ref))
		item = root->item;
	if (!item && root->right)
		item = ft_btree_search_item(root->right, data_ref, cmpf);
	return (item);
}
