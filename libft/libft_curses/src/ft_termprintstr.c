/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termprintstr.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/25 22:52:39 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 20:19:42 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int		ft_termprintstr(char *s, t_term *term)
{
	int		size;

	printw("%s", s);
	size = ft_strtablen(s, 8);
	ft_termaddcol(term, size);
	refresh();
	return (0);
}
