/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termnew.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 17:43:53 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/07 18:43:31 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"
#include <stdlib.h>

static void		set_term_struct(t_term *term, char **environ)
{
	term->env = environ;
	term->pos = 0;
	term->prompt = NULL;
	term->prompt_len = 0;
	term->hist = NULL;
	term->comp = NULL;
	term->cmds = NULL;
	term->options = NULL;
	term->str_color = none;
	term->prompt_color = none;
	term->win = NULL;
	term->screen = NULL;
	term->error = NULL;
	term->comp_buffer = NULL;
}

static t_term	*term_exit(t_term *new, char **error)
{
	if (!new || (new && !new->error))
		*error = ft_strdup(FT_TERM_ERROR_MEMALLOC);
	if (new)
	{
		if (new->error)
			*error = new->error;
		if (new->buffer)
			free(new->buffer);
		free(new);
	}
	ft_termexit();
	return (NULL);
}

t_term			*ft_termnew(int opt, char **environ, char **error)
{
	t_term	*new;

	*error = NULL;
	if (!(new = (t_term *)malloc(sizeof(t_term))))
		return (term_exit(NULL, error));
	if (!(new->buffer = ft_strnew(FT_TERM_BUFFSIZE)))
		return (term_exit(new, error));
	set_term_struct(new, environ);
	new->opt = opt;
	if (ft_terminit(new))
		return (term_exit(new, error));
	ft_termsize(new);
	return (new);
}
