/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_create_node.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 13:57:13 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/16 17:40:55 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

t_btree		*ft_btree_create_node(void *item, size_t size)
{
	t_btree	*new;

	if (!(new = ft_memalloc(sizeof(t_btree))))
		return (NULL);
	if (!(new->item = ft_memalloc(size)))
	{
		free(new);
		return (NULL);
	}
	ft_memcpy(new->item, item, size);
	new->size = size;
	new->left = NULL;
	new->right = NULL;
	new->parent = NULL;
	new->color = b_red;
	return (new);
}
