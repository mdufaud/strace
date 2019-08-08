/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termgnl.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/24 15:57:51 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/09 12:09:42 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

static const t_termcode	g_tabcode[] = {
	{FT_TERM_OK, "Ok"},
	{FT_TERM_READ, "Read"},
	{FT_TERM_EXIT, "Exit"},
	{FT_TERM_ERROR, "Error"},
	{FT_TERM_MALLOC_ERROR, "Malloc Error"},
	{0, "Termcaps ok"},
	{-1, "Termcaps error"},
	{-2, "Unknown Code !"}
};

int			print_err_code(int err_code)
{
	int		i;

	i = 0;
	while (g_tabcode[i].code != 0)
	{
		if (err_code == g_tabcode[i].code)
		{
			printf(" LibTermcaps error code %d: %s ",
					g_tabcode[i].code, g_tabcode[i].name);
			return (1);
		}
		i++;
	}
	printf(" LibTermcaps error code %d: %s ",
			g_tabcode[i].code, g_tabcode[i].name);
	return (0);
}

int			ft_term_noblock_gnl(char **line, t_term *term)
{
	int		key;
	int		ret;
	int		err_code;

	(void)err_code;
	*line = NULL;
	ret = 0;
	term->code = FT_TERM_READ;
	if (ft_termcanread(term) && (ret = ft_termread(&key, term)) > 0)
		err_code = ft_termgetkey(key, term);
	refresh();
	if (ft_strchr(term->buffer, '\n'))
	{
		*line = ft_strdup(term->buffer);
		ft_bzero(term->buffer, FT_TERM_BUFFSIZE);
		term->pos = 0;
		ret = ft_strlen(*line);
	}
	if ((term->code & FT_TERM_EXIT))
		return (-1);
	if ((term->code & FT_TERM_ERROR))
		return (-2);
	return (ret);
}

int			ft_termgnl(char **line, t_term *term)
{
	int		key;
	int		ret;
	int		err_code;

	(void)err_code;
	term->code = FT_TERM_READ;
	while (ft_termcanread(term) && (ret = ft_termread(&key, term)) > 0)
		err_code = ft_termgetkey(key, term);
	*line = ft_strdup(term->buffer);
	ft_bzero(term->buffer, FT_TERM_BUFFSIZE);
	term->pos = 0;
	if ((term->code & FT_TERM_EXIT))
		return (-1);
	if ((term->code & FT_TERM_ERROR))
		return (-2);
	return (ft_strlen(*line));
}
