/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/19 19:31:00 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/24 15:47:29 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
# define LIBFT_H

# include "debug.h"
# include <string.h>

# define NONE 0
# define VERBOSE 1

# define TRUE 1
# define FALSE 0

# define ABS(x) (x < 0 ? -x : x)
# define MAX(a,b) (a > b ? a : b)
# define MIN(a,b) (a < b ? a : b)

/*
** Mask macro
*/

# define LOWER (2 << 0)
# define UPPER (2 << 1)
# define HEXA (2 << 2)
# define HEXA_UPPER (2 << 3)

/*
** Binary tree
*/

typedef enum		e_rb_color
{
	b_black,
	b_red
}					t_rb_color;

typedef struct		s_btree
{
	struct s_btree	*parent;
	struct s_btree	*left;
	struct s_btree	*right;
	void			*item;
	size_t			size;
	t_rb_color		color;
}					t_btree;

/*
** Dual linked list struct
*/

typedef struct		s_dlist
{
	void			*content;
	size_t			content_size;
	struct s_dlist	*next;
	struct s_dlist	*prev;
}					t_dlist;

/*
** Linked list struct
*/

typedef struct		s_list
{
	void			*content;
	size_t			content_size;
	struct s_list	*next;
}					t_list;

/*
** Color enumeration
*/

# ifndef LIBFT_COLOR
#  define LIBFT_COLOR

typedef enum		e_color
{
	none,
	red,
	bourg,
	white,
	blue,
	dark,
	purple,
	cyan,
	yellow,
	green,
	pink,
	end_color
}					t_color;

# endif

typedef struct		s_text_to_color
{
	char			*text;
	t_color			color;
}					t_text_to_color;

/*
** Tab functions
*/

char				**ft_tabinit(size_t size);
char				**ft_tabadd(char **tab, char *s);
char				**ft_tabdel(char **tab, int index);
void				ft_tabfree(char ***tab);
char				**ft_tabreplace(char **tab, char *s, int index);
int					ft_tabfind(char **tab, char *s);
int					ft_tabcount(char **tab);
char				**ft_tabslip(char **tab, char *s, int index);
int					ft_tablen(char **tab);
char				**ft_tabdup(char **tab);
void				ft_tabprint(char **tab);
void				ft_tabprint_fd(char **tab, int fd);
char				**ft_tabnew(size_t col);
char				**ft_tabjoin(char **tab1, char **tab2);

/*
** String operations
*/

int					ft_strisdigit(char *s);
int					ft_strcmp(const char *s1, const char *s2);
int					ft_strncmp(const char *s1, const char *s2, size_t n);
int					ft_strequ(char const *s1, char const *s2);
int					ft_strnequ(char const *s1, char const *s2, size_t n);
int					ft_strclen(char *s, int n);
int					ft_strnchar(char *s, int n);
char				*ft_strdup(const char *s);
char				*ft_strcpy(char *s1, const char *s2);
char				*ft_strncpy(char *s1, const char *s2, size_t n);
char				*ft_strcat(char *s1, const char *s2);
char				*ft_strncat(char *s1, const char *s2, size_t n);
char				*ft_strchr(const char *s, int c);
char				*ft_strrchr(const char *s, int c);
char				*ft_strstr(const char *s1, const char *s2);
int					ft_strcfind(const char *s, int n);
char				*ft_strnstr(const char *s1, const char *s2, size_t n);
char				*ft_strnew(size_t size);
char				*ft_strsub(char const *s, unsigned int start, size_t len);
char				*ft_strsubi(char const *s, int start, int end);
char				*ft_strjoin(char const *s1, char const *s2);
char				*ft_strtjoin(char *s1, char *s2, char *s3);
char				*ft_strjoin_free(char **s, char const *s2);
char				*ft_strtrim(char *s);
char				**ft_strsplit(char const *s, char c);
char				**ft_strfsplit(char const *s, int (*f)(char));
char				*ft_strmap(char const *s, char (*f)(char));
char				*ft_strmapi(char const *s, char (*f)(unsigned int, char));
char				*ft_strdup_free(char *s);
char				*ft_strsub_free(char *s, size_t start, size_t len);
void				ft_striter(char *s, void (*f)(char *));
void				ft_striteri(char *s, void (*f)(unsigned int, char *));
void				ft_strdel(char **as);
void				ft_strclr(char *s);
size_t				ft_strlen(const char *s);
size_t				ft_strlcat(char *dst, const char *src, size_t size);
void				ft_swap_s(char **s1, char **s2);
int					ft_toupper(int c);
int					ft_tolower(int c);
char				ft_toupper_char(char c);
char				ft_tolower_char(char c);
char				*ft_sub(char *s, int start, int end);
char				*ft_epur(char *s);
int					ft_strismap(char *s, int (*f)(int));
void				ft_strtomap(char *s, int (*f)(int));
int					ft_strcount(char *s, char c);
int					ft_strtablen(char *s, int tab_stop);
char				*ft_strreplace(char *s, char *from, char *to);
char				*ft_strunion(char **tab, char *unite);

/*
** Check operations
*/

int					ft_isalpha(int c);
int					ft_isdigit(int c);
int					ft_isalnum(int c);
int					ft_isascii(int c);
int					ft_isprint(int c);
int					ft_isspace(char c);

/*
** Dual linked list operations
*/

t_dlist				*ft_dlstnew(void const *content, size_t content_size);
void				ft_dlstadd(t_dlist **alst, t_dlist *new);
void				ft_dlstdelone(t_dlist **alst, void (*del)(void *, size_t));
void				ft_dlstdel(t_dlist **alst, void (*del)(void *, size_t));
void				ft_dlstfirst(t_dlist **alst);
void				ft_dlstlast(t_dlist **alst);

/*
** Linked list operations
*/

void				ft_lstdelone(t_list **alst, void (*del)(void *, size_t));
void				ft_lstdel(t_list **alst, void (*del)(void *, size_t));
void				ft_lstadd(t_list **alst, t_list *new);
void				ft_lstiter(t_list *lst, void (*f)(t_list *elem));
t_list				*ft_lstnew(void const *content, size_t content_size);
t_list				*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem));

/*
** Memory operations
*/

int					ft_memcmp(const void *s1, const void *s2, size_t n);
void				*ft_memset(void *b, int c, size_t len);
void				ft_bzero(void *s, size_t n);
void				*ft_memcpy(void *s1, const void *s2, size_t n);
void				*ft_memccpy(void *s1, const void *s2, int c, size_t n);
void				*ft_memmove(void *s1, const void *s2, size_t n);
void				*ft_memchr(const void *s, int c, size_t n);
void				*ft_memalloc(size_t size);
void				ft_memdel(void **ap);
long				ft_byteswap(long num);
void				ft_hexdump(void *mem, unsigned int size);
char				*ft_hexdump_s(void *mem, unsigned int size);

/*
** Number operations
*/

long long			ft_atob(const char *str, int base);
int					ft_isbase(int n, int base);
char				ft_getbase(int n);
char				ft_basechar(int n, int upper);
char				*ft_btoa(long long n, int base, int mask);
char				*ft_ltoa(long n);
int					ft_atoi(const char *str);
size_t				ft_numsize(long long num, unsigned int base);
char				*ft_itoa(int n);
char				*ft_lltoa(long long n);
char				*ft_uitoa(unsigned int n);
char				*ft_ltoa_base(long n, int base);
char				*ft_lltoa_base(long long n, int base);
char				*ft_ultoa_base(unsigned long n, int base);
unsigned int		ft_atoui(const char *str);
long long			ft_atoll(const char *str);
char				*ft_ulltoa(unsigned long long n);

/*
** Print operations
*/

void				ft_puthex(unsigned int n);
void				ft_putbase(long n, int base);
void				ft_putbin(long n);
void				ft_put_color(t_color color);
void				ft_put_color_fd(int fd, t_color color);
void				ft_end_color(void);
void				ft_end_color_fd(int fd);
void				ft_putstr(char const *s);
void				ft_putnbr(int n);
void				ft_putnbrendl(int n);
void				ft_putcnbr(int n, t_color color);
void				ft_putcnbrendl(int n, t_color color);
void				ft_putcnbr_fd(int n, int fd, t_color color);
void				ft_putcnbrendl_fd(int n, int fd, t_color color);
void				ft_putlong(long n);
void				ft_putlongendl(long n);
void				ft_putendl(char const *s);
void				ft_putchar(int c);
void				ft_putchar_fd(int c, int fd);
void				ft_putstr_fd(char const *s, int fd);
void				ft_putendl_fd(char const *s, int fd);
void				ft_putnbr_fd(int n, int fd);
void				ft_putdstr(char *s1, char *s2);
void				ft_putdendl(char *s1, char *s2);
void				ft_putdstr_fd(char *s1, char *s2, int fd);
void				ft_putdendl_fd(char *s1, char *s2, int fd);
void				ft_putcstr(char *s, t_color color);
void				ft_putcchar(int c, t_color color);
void				ft_putcstr_fd(char *s, int fd, t_color color);
void				ft_putcendl(char *s, t_color color);
void				ft_putcendl_fd(char *s, int fd, t_color color);
void				ft_putendltab(char *s);
int					ft_error(char *error);
int					ft_error_file(char *error, char *file);
int					ft_error_verbose(char *err, char *reason);
char				*ft_projname(char *projname);
void				ft_print_list(int *l, unsigned int size);
void				ft_printaddr(void *addr);
void				ft_debugaddr(char *s, void *addr);
t_color				ft_getcolorfromtext(char *text);
int					ft_strcmp_map(const char *str1,
									const char *str2, char (*f)(char));

/*
** Double linked list operations
*/

/*
** List operations
*/

/*
** List tab operations
*/

/*
** Binary tree operations
*/

t_btree				*ft_btree_create_node(void *item, size_t size);
void				ft_btree_apply_prefix(t_btree *root,
												void (*f)(void *, size_t));
void				ft_btree_apply_infix(t_btree *root,
												void (*f)(void *, size_t));
void				ft_btree_apply_suffix(t_btree *root,
												void (*f)(void *, size_t));
void				ft_btree_insert_data(t_btree **root, void *item,
									size_t size, int (*cmpf)(void *, void *));
int					ft_btree_cmp(void *item1, void *item2);
size_t				ft_btree_size(t_btree *root);
void				ft_btree_printf(t_btree *root,
										void (*printfun)(void *, size_t),
										size_t (*lenfun)(void *, size_t));
void				*ft_btree_search_item(t_btree *root, void *data_ref,
												int (*cmpf)(void *, void *));
void				ft_btree_repare(t_btree **root, t_btree *node);
void				ft_btree_rotate_left(t_btree **root, t_btree *node);
void				ft_btree_rotate_right(t_btree **root, t_btree *node);
t_btree				*ft_btree_uncle(t_btree *node);
size_t				ft_btree_sizeint(void *item, size_t size);
size_t				ft_btree_sizestr(void *item, size_t size);
void				ft_btree_printint(void *item, size_t size);
void				ft_btree_printstr(void *item, size_t size);
void				ft_btree_remove(t_btree **root, void *data,
								int (*cmpf)(void *, void *),
								void (*freefun)(void *, size_t));

t_btree				*ft_btree_search_node(t_btree *root, void *data_ref,
								int (*cmpf)(void *, void *));
t_btree				*ft_btree_search_min_node(t_btree *root);
t_btree				*ft_btree_search_max_node(t_btree *root);

/*
** To sort
*/

int					ft_retint_free(int fd, char **s, char ***tab, void **data);
void				*ft_retptr_free(int fd, char **s, char ***tab, void **data);
int					ft_send(char *s, int socket);
int					ft_sendendl(char *s, int socket);
void				ft_csend(char *s, t_color color, int co);

#endif
