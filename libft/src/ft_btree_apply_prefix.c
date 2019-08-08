/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_apply_prefix.c                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 14:05:27 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/16 14:08:52 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_btree_apply_prefix(t_btree *root, void (*f)(void *, size_t))
{
	if (!root)
		return ;
	f(root->item, root->size);
	if (root->left)
		ft_btree_apply_prefix(root->left, f);
	if (root->right)
		ft_btree_apply_prefix(root->right, f);
}
