/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_uncle.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 17:51:16 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/16 17:51:21 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_btree			*ft_btree_uncle(t_btree *node)
{
	t_btree		*grand_parent;

	if (!node->parent || !node->parent->parent)
		return (NULL);
	grand_parent = node->parent->parent;
	if (node->parent == grand_parent->left)
		return (grand_parent->right);
	return (grand_parent->left);
}
