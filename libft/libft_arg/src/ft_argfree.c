/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_argfree.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/04 21:25:26 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 15:54:15 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_arg.h"
#include <stdlib.h>

void	ft_argfree(t_arg **arg)
{
	ft_tabfree(&(*arg)->arglist);
	ft_tabfree(&(*arg)->argv);
	if ((*arg)->error)
		ft_strdel(&(*arg)->error);
	free((*arg));
	*arg = NULL;
}
