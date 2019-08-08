/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_keytab_options.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 15:58:26 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/10 11:21:43 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"
#include <stdlib.h>

static char		*get_word(char *s, int index)
{
	int		beg;
	int		end;
	int		i;

	i = 0;
	if (index < 0)
		return (NULL);
	while (index + i >= 0 && s[index + i] && !ft_isspace(s[index + i]))
		i--;
	beg = index + i;
	if (ft_isspace(s[beg]))
		beg += 1;
	i = 0;
	while (s[index + i] && !ft_isspace(s[index + i]))
		i++;
	end = index + i;
	if (end - beg <= 0)
		return (NULL);
	return (ft_strsub(s, beg, end - beg));
}

static void		create_lst(t_term *term, char **options)
{
	int		i;
	int		len;
	int		option_len;
	t_dlist	*new;
	char	*word;

	i = 0;
	word = get_word(term->buffer, term->pos - 1);
	len = word ? ft_strlen(word) : 0;
	while (options[i])
	{
		option_len = ft_strlen(options[i]);
		if (!len || (!ft_strncmp(options[i], word, len)
					&& option_len - len > 0))
		{
			new = ft_dlstnew(options[i] + len, option_len - len + 1);
			ft_dlstadd(&term->comp, new);
		}
		i++;
	}
	free(word);
}

void			ft_keytab_options(t_term *term, char *cmd)
{
	char	**options;

	if (!cmd)
		return ;
	if (ft_hashfind(&term->options, cmd))
	{
		options = term->options->value;
		create_lst(term, options);
	}
}
