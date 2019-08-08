/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_keydel.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 20:41:34 by mdufaud           #+#    #+#             */
/*   Updated: 2016/11/27 19:23:37 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int			ft_keydel(t_term *term)
{
	char	*tmp;

	if (term->buffer[term->pos])
	{
		tmp = term->buffer + term->pos;
		ft_memmove(tmp, tmp + 1, ft_strlen(tmp) + 1);
		ft_termrewrite(term->buffer, term);
	}
	return (1);
}
