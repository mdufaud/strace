/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_keytab.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/24 16:24:34 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 16:52:26 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"
#include <stdlib.h>

static void		set_compares(t_term *term)
{
	char	*tmp;

	if (!term->comp || !term->comp->content_size)
		return ;
	if (!(tmp = ft_strjoin(term->buffer, term->comp->content)))
		return ;
	if (term->comp_buffer)
		free(term->comp_buffer);
	term->comp_buffer = tmp;
	ft_termresetline(term->comp_buffer, term);
}

static void		complete_cmds(t_term *term, char *cmd)
{
	int		len;
	t_dlist	*new;
	t_dlist	*first;

	len = ft_strlen(cmd);
	ft_dlstfirst(&term->cmds);
	first = term->cmds;
	while (term->cmds)
	{
		if (!ft_strncmp(term->cmds->content, cmd, len))
		{
			new = ft_dlstnew(term->cmds->content + len,
							term->cmds->content_size - len);
			ft_dlstadd(&term->comp, new);
		}
		term->cmds = term->cmds->next;
	}
	term->cmds = first;
}

static int		create_compares(t_term *term, char **split)
{
	if (ft_tablen(split) == 1
			&& (term->pos > 0 && term->buffer[term->pos - 1] != ' ')
			&& term->cmds)
		complete_cmds(term, split[0]);
	else if (term->options && !term->buffer[term->pos])
		ft_keytab_options(term, split[0]);
	set_compares(term);
	return (FT_TERM_OK);
}

int				ft_keytab(t_term *term)
{
	char	**split;

	split = NULL;
	if (term->pos <= 0)
		return (FT_TERM_ERROR);
	if (!term->comp)
	{
		if (!(split = ft_strsplit(term->buffer, ' ')))
			return (FT_TERM_MALLOC_ERROR);
		create_compares(term, split);
		ft_tabfree(&split);
	}
	else if (term->pos > 0 && term->buffer[term->pos - 1] != ' ')
	{
		if (term->comp->next)
			term->comp = term->comp->next;
		else
			ft_dlstfirst(&term->comp);
		set_compares(term);
	}
	return (FT_TERM_OK);
}
