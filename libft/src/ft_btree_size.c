/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_size.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 15:07:40 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/16 15:17:03 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t		ft_btree_size(t_btree *root)
{
	int		right;
	int		left;

	if (!root)
		return (0);
	left = 1 + ft_btree_size(root->left);
	right = 1 + ft_btree_size(root->right);
	if (left > right)
		return (left);
	return (right);
}
