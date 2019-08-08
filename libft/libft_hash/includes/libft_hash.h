/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_hash.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 16:18:30 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 16:59:45 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_HASH_H
# define LIBFT_HASH_H

# include "libft.h"

/*
** Hash macro
*/

# define HASH_ADD(hash,stuff) ft_hashadd(&hash, stuff)
# define HASH_INT(key,value) ft_hashnew(key, &value, type_int, sizeof(int))
# define HASH_CHAR(key,value) ft_hashnew(key, &value, type_char, sizeof(char))
# define HASH_ADDR(k,v) ft_hashnew(k, v, type_addr, sizeof(void *))
# define HASH_STR(k,v) ft_hashnew(k, v, type_str, ft_strlen(k))
# define HASH_LIST(k,v,s) ft_hashnew(k, v, type_lst, s)
# define HASH_TAB(k,v) ft_hashnew(k, v, type_tab, ft_tablen(v))

/*
** Hash types enum
*/

typedef enum		e_type
{
	type_int,
	type_char,
	type_addr,
	type_str,
	type_tab,
	type_lst
}					t_type;

/*
** Hash struct
*/

typedef struct		s_hash
{
	char			*key;
	void			*value;
	t_type			type;
	size_t			size;
	struct s_hash	*next;
	struct s_hash	*prev;
	struct s_hash	*first;
}					t_hash;

/*
** Hash functions
*/

t_hash				*ft_hashnew(char *key, void *d, t_type type, size_t size);
void				ft_hashadd(t_hash **old, t_hash *new);
void				ft_hashprint(t_hash *hash, int index);
void				ft_hashprintendl(t_hash *hash, int index);
void				ft_hashprint_all(t_hash *hash);
void				ft_hashfree(t_hash **hash);
void				ft_hashfree_allocated(t_hash **hash);
void				ft_hashdebug(t_hash *hash);
void				ft_hashfree_value(t_hash *hash);
int					ft_hashfind(t_hash **hash, char *key);
int					ft_hashdel(t_hash **hash, char *key);
void				ft_print_t_type(t_type type);

#endif
