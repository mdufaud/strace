/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termgetkey.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 17:28:42 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 15:55:37 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

static const t_termkey	g_tabkey[] = {
	{FT_TERM_KEY_RETURN, &ft_keyreturn},
	{KEY_ENTER, &ft_keyreturn},
	{KEY_EXIT, &ft_keyexit},
	{FT_TERM_CTRL_C, &ft_keyexit},
	{FT_TERM_KEY_BACKSPACE, &ft_keybackdel},
	{KEY_BACKSPACE, &ft_keybackdel},
	{KEY_DC, &ft_keydel},
	{KEY_UP, &ft_keyarrowup},
	{KEY_DOWN, &ft_keyarrowdown},
	{KEY_RIGHT, &ft_keyarrowright},
	{KEY_LEFT, &ft_keyarrowleft},
	{KEY_HOME, &ft_keyhome},
	{KEY_END, &ft_keyend},
	{'\t', &ft_keytab},
	{-1, NULL}
};

void		ft_debugkey(int key, int d_key)
{
	endwin();
	printf("Key: %d\n", key);
	printf("Desired key: %d\n", d_key);
	exit(0);
}

int			ft_termresize(t_term *term)
{
	getmaxyx(term->win, term->max_row, term->max_col);
	return (1);
}

int			ft_termgetkey(int key, t_term *term)
{
	int			i;

	if (key == KEY_RESIZE)
		return (ft_termresize(term));
	if (key != '\t' && term->comp_buffer)
		ft_termvalidatetab(term);
	i = 0;
	while (g_tabkey[i].keycode > 0)
	{
		if (key == g_tabkey[i].keycode)
			return (g_tabkey[i].f(term));
		i++;
	}
	ft_keyadd(key, term);
	refresh();
	ft_dlstfirst(&term->hist);
	return (-1);
}
