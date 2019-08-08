/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_apply_suffix.c                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 14:11:35 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/16 14:12:34 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_btree_apply_infix(t_btree *root, void (*f)(void *, size_t))
{
	if (!root)
		return ;
	if (root->left)
		ft_btree_apply_suffix(root->left, f);
	if (root->right)
		ft_btree_apply_suffix(root->right, f);
	f(root->item, root->size);
}
