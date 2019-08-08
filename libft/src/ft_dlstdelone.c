/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_dlstdelone.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 16:30:15 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 22:02:47 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static void		default_del(void *c, size_t s)
{
	ft_bzero(c, s);
	ft_memdel(&c);
}

void			ft_dlstdelone(t_dlist **alst, void (*del_fun)(void *, size_t))
{
	t_dlist		*del;

	del = *alst;
	if (!del->prev)
		*alst = del->next;
	if (del->next)
		del->next->prev = del->prev;
	if (del->prev)
		del->prev->next = del->next;
	if (del_fun)
		(*del_fun)(del->content, del->content_size);
	else
		default_del(del->content, del->content_size);
	ft_bzero(del, sizeof(t_dlist));
	free(del);
}
