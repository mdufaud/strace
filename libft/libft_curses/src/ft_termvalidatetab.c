/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termvalidatetab.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 18:45:05 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/07 18:52:17 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termvalidatetab(t_term *term)
{
	if (term->comp_buffer)
	{
		ft_strcpy(term->buffer, term->comp_buffer);
		free(term->comp_buffer);
		term->comp_buffer = NULL;
	}
	if (term->comp)
	{
		ft_dlstdel(&term->comp, NULL);
	}
}
