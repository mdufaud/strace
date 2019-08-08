/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_getcolorfromtext.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 14:39:54 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/15 14:33:32 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static const t_text_to_color	g_txt_color_tab[] = {
	{"red", red},
	{"green", green},
	{"yellow", yellow},
	{"blue", blue},
	{"cyan", cyan},
	{"bourg", bourg},
	{"pink", pink},
	{"white", white},
	{NULL, none}
};

t_color		ft_getcolorfromtext(char *text)
{
	int		i;

	i = 0;
	while (g_txt_color_tab[i].text)
	{
		if (!ft_strcmp_map(g_txt_color_tab[i].text, text, &ft_tolower_char))
			return (g_txt_color_tab[i].color);
		i++;
	}
	return (none);
}
