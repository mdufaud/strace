/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_curses.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 16:18:30 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 19:48:14 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_CURSES_H
# define LIBFT_CURSES_H

# include "libft.h"
# include "libft_hash.h"
# include <curses.h>

# include <stdlib.h>

# define FT_TERM_BUFFSIZE 2048
# define FT_TERM_NOHISTORY (2 << 0)
# define FT_TERM_PROMPT (2 << 1)
# define FT_TERM_STR (2 << 2)

# define FT_TERM_ERROR_INIT "Ncurses init error"
# define FT_TERM_ERROR_RAW "Ncurses raw error"
# define FT_TERM_ERROR_KEYPAD "Ncurses keypad error"
# define FT_TERM_ERROR_ECHO "Ncurses echo error"
# define FT_TERM_ERROR_MEMALLOC "Ncurses malloc error"
# define FT_TERM_ERROR_GENERIC "Ncurses error"

# define FT_TERM_OK (2 << 0)
# define FT_TERM_READ (2 << 1)
# define FT_TERM_EXIT (2 << 2)
# define FT_TERM_ERROR (2 << 3)
# define FT_TERM_MALLOC_ERROR (2 << 4)

# define FT_TERM_CTRL_C 3
# define FT_TERM_KEY_RETURN 10
# define FT_TERM_KEY_BACKSPACE 127

# define FT_TERM_RED 1
# define FT_TERM_GREEN 2
# define FT_TERM_YELLOW 3
# define FT_TERM_BLUE 4
# define FT_TERM_CYAN 5
# define FT_TERM_MAGENTA 6
# define FT_TERM_WHITE 7

typedef struct		s_term
{
	char			*prompt;
	char			**env;
	char			*buffer;
	char			*comp_buffer;
	char			*error;
	int				opt;
	int				pos;
	int				prompt_len;
	int				max_row;
	int				max_col;
	int				reload_pos;
	int				reload_col;
	int				reload_row;
	int				row;
	int				col;
	int				last_prompt_row;
	int				code;
	t_color			prompt_color;
	t_color			str_color;
	t_dlist			*hist;
	t_dlist			*comp;
	t_dlist			*cmds;
	t_hash			*options;
	WINDOW			*win;
	SCREEN			*screen;
}					t_term;

typedef struct		s_termkey
{
	int				keycode;
	int				(*f)(t_term *);
}					t_termkey;

typedef struct		s_termcode
{
	int				code;
	char			*name;
}					t_termcode;

typedef struct		s_term_compat_libft_color
{
	t_color			libft_color;
	int				term_color;
}					t_term_compat_libft_color;

t_term				*ft_termnew(int opt, char **environ, char **error);
int					ft_terminit(t_term *term);
void				ft_termdescribe(t_term *term);
void				ft_termsize(t_term *term);
void				ft_termexit(void);
void				ft_termprompt(t_term *term);
void				ft_termsetprompt(char *s, t_term *term);
void				ft_termdel(t_term **term);
int					ft_termread(int *key, t_term *term);
int					ft_termgetkey(int key, t_term *term);
int					ft_termgnl(char **line, t_term *term);
int					ft_termputs(int c);
void				ft_termhome(t_term *term);
int					ft_termcanread(t_term *term);
void				ft_termaddcmd(t_term *term, char *cmds);
void				ft_termaddoptions(t_term *term, t_hash *hash);
void				ft_termrewrite(char *s, t_term *term);
void				ft_termresetline(char *s, t_term *term);
void				ft_termsetcolor(t_term *term, int opt, t_color color);
void				ft_termvalidatetab(t_term *term);
void				ft_termclearline(t_term *term);
void				ft_termreloadline(t_term *term);
int					ft_term_noblock_gnl(char **line, t_term *term);

int					ft_keyreturn(t_term *term);
int					ft_keyhome(t_term *term);
int					ft_keyend(t_term *term);
int					ft_keytab(t_term *term);
void				ft_keytab_options(t_term *term, char *cmd);
int					ft_keyexit(t_term *term);
int					ft_keybackdel(t_term *term);
int					ft_keydel(t_term *term);
int					ft_keyarrowright(t_term *term);
int					ft_keyarrowleft(t_term *term);
int					ft_keyarrowup(t_term *term);
int					ft_keyarrowdown(t_term *term);
int					ft_keyadd(int key, t_term *term);

int					ft_termprint(int key, t_term *term);
int					ft_termputcolor(t_color color);
int					ft_termprintstr(char *s, t_term *term);
int					ft_termprintcstr(char *s, t_color color, t_term *term);
int					ft_termprintendl(char *s, t_term *term);
int					ft_termprintcendl(char *s, t_color color, t_term *term);

void				ft_termaddcol(t_term *term, int size);

#endif
