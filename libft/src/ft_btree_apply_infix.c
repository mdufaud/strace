/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_apply_infix.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 14:09:20 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/16 14:12:01 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_btree_apply_infix(t_btree *root, void (*f)(void *, size_t))
{
	if (!root)
		return ;
	if (root->left)
		ft_btree_apply_infix(root->left, f);
	f(root->item, root->size);
	if (root->right)
		ft_btree_apply_infix(root->right, f);
}
