/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termresetline.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/24 18:11:11 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 18:08:44 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termresetline(char *s, t_term *term)
{
	ft_termhome(term);
	term->pos = ft_strlen(s);
	clrtobot();
	ft_termprintcstr(s, term->str_color, term);
}
