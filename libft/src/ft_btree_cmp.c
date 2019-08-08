/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_btree_cmp.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 14:39:51 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/17 15:01:03 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int			ft_btree_cmp(void *item1, void *item2)
{
	char	*s1;
	char	*s2;

	s1 = (char *)item1;
	s2 = (char *)item2;
	return (ft_strcmp(s1, s2));
}
