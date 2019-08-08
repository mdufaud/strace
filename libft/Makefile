# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2013/11/19 14:45:20 by mdufaud           #+#    #+#              #
#    Updated: 2017/11/28 22:23:40 by mdufaud          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

OS := $(shell uname)
ifeq ($(OS),Linux)
SHELL := /bin/bash
else
SHELL := /bin/sh
endif

ifeq ($(OS),Linux)
ECHO = echo -e
else
ECHO = echo
endif

NAME = libft.a

RED_COLOR = \033[31m
LIGHT_RED_COLOR = \033[1;31m
YELLOW_COLOR = \033[1;33m
BROWN_COLOR = \033[33m
GREEN_COLOR = \033[32m
LIGHT_GREEN_COLOR = \033[32;01m
CYAN_COLOR = \033[36m
LIGHT_CYAN_COLOR = \033[1;36m
PURPLE_COLOR = \033[35m
LIGHT_PURPLE_COLOR = \033[1;35m
BLUE_COLOR = \033[34m
LIGHT_BLUE_COLOR = \033[1;34m
LIGHT_GRAY_COLOR = \033[37m
DARK_GRAY_COLOR = \033[1;30m
BLACK_COLOR = \033[30m
WHITE_COLOR = \033[1;37m
END_COLOR = \033[00m

COFFEE = ☕️
POPCORN = 🍿

CFLAGS = cc -Wall -Wextra -Werror
IFLAGS = -I includes
PATH_SRC = src
PATH_OBJ = obj
FIRST_SRC = 1
CURSES_PATH = libft_curses 
ARG_PATH = libft_arg 
HASH_PATH = libft_hash
PRINTF_PATH = libft_printf

SRC = ft_atoi.c\
	  ft_putcnbr.c\
	  ft_dlstnew.c\
	  ft_dlstadd.c\
	  ft_dlstdel.c\
	  ft_dlstdelone.c\
	  ft_dlstfirst.c\
	  ft_dlstlast.c\
	  ft_hexdump.c\
	  ft_hexdump_s.c\
	  ft_atob.c\
	  ft_strcount.c\
	  ft_strtablen.c\
	  ft_isbase.c\
	  ft_getbase.c\
	  ft_btoa.c\
	  ft_basechar.c\
	  ft_strunion.c\
	  ft_numsize.c\
	  ft_putbase.c\
	  ft_puthex.c\
	  ft_tabjoin.c\
	  ft_putcchar.c\
	  ft_strisdigit.c\
	  ft_tabnew.c\
	  ft_putcnbrendl.c\
	  ft_putcnbr_fd.c\
	  ft_putcnbrendl_fd.c\
	  ft_put_color.c\
	  ft_put_color_fd.c\
	  ft_end_color.c\
	  ft_end_color_fd.c\
	  ft_getcolorfromtext.c\
	  ft_strcmp_map.c\
	  ft_tolower_char.c\
	  ft_toupper_char.c\
	  ft_putlong.c\
	  ft_putlongendl.c\
	  ft_putnbrendl.c\
	  ft_error.c\
	  ft_error_verbose.c\
	  ft_error_file.c\
	  ft_projname.c\
	  ft_retint_free.c\
	  ft_retptr_free.c\
	  ft_tabprint.c\
	  ft_tabprint_fd.c\
	  ft_tabinit.c\
	  ft_tabadd.c\
	  ft_tabdel.c\
	  ft_tabfind.c\
	  ft_tabreplace.c\
	  ft_tabcount.c\
	  ft_tabfree.c\
	  ft_tabslip.c\
	  ft_csend.c\
	  ft_send.c\
	  ft_sendendl.c\
	  ft_putbin.c\
	  ft_byteswap.c\
	  ft_printaddr.c\
	  ft_debugaddr.c\
	  ft_bzero.c\
	  ft_debugc.c\
	  ft_strlcat.c\
	  ft_debugchar.c\
	  ft_debugfun.c\
	  ft_debugnbr.c\
	  ft_debugn.c\
	  ft_debugs.c\
	  ft_debugstr.c\
	  ft_debugstrn.c\
	  ft_epur.c\
	  ft_isalnum.c\
	  ft_isalpha.c\
	  ft_isascii.c\
	  ft_isprint.c\
	  ft_isdigit.c\
	  ft_isspace.c\
	  ft_itoa.c\
	  ft_atoll.c\
	  ft_ulltoa.c\
	  ft_ltoa_base.c\
	  ft_lltoa_base.c\
	  ft_ultoa_base.c\
	  ft_atoui.c\
	  ft_lltoa.c\
	  ft_uitoa.c\
	  ft_lstadd.c\
	  ft_lstnew.c\
	  ft_memalloc.c\
	  ft_memccpy.c\
	  ft_memchr.c\
	  ft_memdel.c\
	  ft_memcmp.c\
	  ft_memcpy.c\
	  ft_memmove.c\
	  ft_memset.c\
	  ft_print_list.c\
	  ft_putcendl.c\
	  ft_putcendl_fd.c\
	  ft_putendltab.c\
	  ft_putdendl.c\
	  ft_putendl.c\
	  ft_putendl_fd.c\
	  ft_putdendl_fd.c\
	  ft_putchar.c\
	  ft_putstr_fd.c\
	  ft_strclen.c\
	  ft_strequ.c\
	  ft_strjoin_free.c\
	  ft_strlen.c\
	  ft_strtjoin.c\
	  ft_tabdup.c\
	  ft_tablen.c\
	  ft_putchar_fd.c\
	  ft_putdstr.c\
	  ft_putdstr_fd.c\
	  ft_putcstr.c\
	  ft_putcstr_fd.c\
	  ft_putnbr.c\
	  ft_putnbr_fd.c\
	  ft_putstr.c\
	  ft_strcat.c\
	  ft_strchr.c\
	  ft_strclr.c\
	  ft_strcmp.c\
	  ft_strcpy.c\
	  ft_strdel.c\
	  ft_strisdigit.c\
	  ft_strdup.c\
	  ft_strdup_free.c\
	  ft_strncat.c\
	  ft_strnchar.c\
	  ft_strncmp.c\
	  ft_strncpy.c\
	  ft_strnequ.c\
	  ft_strnew.c\
	  ft_strnstr.c\
	  ft_strrchr.c\
	  ft_strsplit.c\
	  ft_strfsplit.c\
	  ft_strstr.c\
	  ft_strsub.c\
	  ft_strsubi.c\
	  ft_strsub_free.c\
	  ft_strjoin.c\
	  ft_strtrim.c\
	  ft_sub.c\
	  ft_tolower.c\
	  ft_toupper.c\
	  ft_striter.c\
	  ft_striteri.c\
	  ft_strmap.c\
	  ft_strmapi.c\
	  ft_lstdel.c\
	  ft_lstdelone.c\
	  ft_lstiter.c\
	  ft_strcfind.c\
	  ft_strismap.c\
	  ft_strtomap.c\
	  ft_strreplace.c\
	  get_next_line.c\
	  get_next_line_utilities.c\
	  ft_btree_create_node.c\
	  ft_btree_apply_prefix.c\
	  ft_btree_apply_infix.c\
	  ft_btree_apply_suffix.c\
	  ft_btree_insert_data.c\
	  ft_btree_print.c\
	  ft_btree_cmp.c\
	  ft_btree_printf.c\
	  ft_btree_search_item.c\
	  ft_btree_size.c\
	  ft_btree_repare.c\
	  ft_btree_rotate.c\
	  ft_btree_uncle.c\
	  ft_btree_remove.c\
	  ft_btree_search_node.c\
	  ft_lstmap.c

OBJ = $(patsubst %.c, $(PATH_OBJ)/%.o, $(SRC))
INCLUDES = includes/libft.h\
		   includes/debug.h\
		   includes/ermac.h\
		   includes/get_next_line.h

COFFEE_{ = $(BROWN_COLOR){$(END_COLOR)
COFFEE_} = $(BROWN_COLOR)}$(END_COLOR)

SRC_N = 0
MODULO = 1

all: $(NAME)

$(PATH_OBJ)/%.o : $(addprefix $(PATH_SRC)/, %.c) $(INCLUDES)
	@mkdir -p $(PATH_OBJ)
	@$(CFLAGS) $(IFLAGS) -o $@ -c $<
	@if [ $(FIRST_SRC) == 1 ]; then \
		$(eval FIRST_SRC = 0) \
		$(ECHO) "$(LIGHT_BLUE_COLOR)          _                                     _ _   		";\
		$(ECHO) "    _ __ | | ___  __ _ ___  ___  __      ____ _(_) |_ 		";\
		$(ECHO) "   |  _ \| |/ _ \/ _\` / __|/ _ \ \ \ /\ / / _\` | | __|	";\
		$(ECHO) "$(COFFEE)  | |_) | |  __/ (_| \__ \  __/  \ V  V / (_| | | |_ $(COFFEE) 	";\
		$(ECHO) "   |  __/|_|\___|\__,_|___/\___|   \_/\_/ \__,_|_|\__|		";\
		$(ECHO) "   |_| $(END_COLOR)                       					";\
		$(ECHO) "                           {				";\
		$(ECHO) "                        {   }				";\
		$(ECHO) "                         }_{ __{			";\
		$(ECHO) "                      .-{   }   }-.		";\
		$(ECHO) "                     (   }     {   )		";\
		$(ECHO) "                     |\`-.._____..-'|		";\
		$(ECHO) "                     |             ;--.	";\
		$(ECHO) "                     |            (__  \	";\
		$(ECHO) "                     |             | )  )	";\
		$(ECHO) "                     |             |/  /	";\
		$(ECHO) "                     |             /  /	";\
		$(ECHO) "                     |            (  /		";\
		$(ECHO) "                     \             Y		";\
		$(ECHO) "                      \`-.._____..-'		";\
		$(ECHO) "$(END_COLOR)"; \
		$(ECHO) "$(POPCORN)  $(LIGHT_GREEN_COLOR)Libft objects : [ $(END_COLOR)\c"; \
	fi
	@if [ $(MODULO) == 0 ]; then \
		$(ECHO) "$(LIGHT_GREEN_COLOR) ]"; \
		$(ECHO) "$(LIGHT_GREEN_COLOR)                   [ .$(END_COLOR)\c"; \
	else \
		$(ECHO) "$(LIGHT_GREEN_COLOR).$(END_COLOR)\c"; \
	fi
	@$(eval SRC_N = $(shell echo $(SRC_N) + 1 | bc))
	@$(eval MODULO = $(shell echo $(SRC_N) % 30 | bc))

$(NAME): $(OBJ)
	@$(ECHO) "$(LIGHT_GREEN_COLOR) ]$(END_COLOR)"
	@ar rcs $@ $^
	@$(ECHO) "$(GREEN_COLOR)"
	@$(ECHO) "    _     _ _      __ _     ____                   	"	
	@$(ECHO) "   | |   (_) |__  / _| |_  |  _ \  ___  _ __   ___ 	"
	@$(ECHO) "   | |   | |  _ \| |_| __| | | | |/ _ \|  _ \ / _ \\	"
	@$(ECHO) "   | |___| | |_) |  _| |_  | |_| | (_) | | | |  __/	"
	@$(ECHO) "   |_____|_|____/|_|  \__| |____/ \___/|_| |_|\___|	"
	@$(ECHO) ""
	@$(ECHO) "$(END_COLOR)"
	@make -C $(PRINTF_PATH) all

lib:
	@make -C $(PRINTF_PATH) all

clean:
	@make -C $(PRINTF_PATH) clean
	@rm -f $(OBJ)
	@$(ECHO) "$(CYAN_COLOR)[ Libft objects deleted ]$(END_COLOR)"

fclean: clean
	@make -C $(PRINTF_PATH) fclean
	@rm -rf $(NAME)
	@rm -df $(PATH_OBJ)
	@$(ECHO) "$(RED_COLOR)[ $(NAME) deleted ]$(END_COLOR)"

re: fclean all

.PHONY: all clean fclean re lib
