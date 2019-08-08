# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Create: 2014/05/18 14:42:57 by mdufaud            #+#    #+#              #
#    Updated: 2017/11/29 14:59:13 by mdufaud          ###   ########.fr        #
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

NAME = ft_strace

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

COMPILATOR = cc

CFLAGS = $(COMPILATOR) -Wall -Wextra -Werror

IFLAG_LIBFT = -I libft/includes
IFLAG_PRINTF = -I libft/libft_printf/includes

LFLAGS = -L libft\
		 -L libft/libft_printf

LFT_FLAGS = -lft -lft_printf

OFLAGS = -I includes $(IFLAG_LIBFT) $(IFLAG_PRINTF)

LIB = libft/libft.a\
	  libft/libft_printf/libft_printf.a

MKLIB = make -C libft
MKLIBS = make -C libft lib

PATH_SRC = srcs
OBJ_PATH = obj
SRC = main.c\
	  error.c\
	  prepare_syscall.c\
	  print_syscall.c\
	  print_syscall_type.c\
	  path.c\
	  get_signame.c\
	  errno.c\
	  signal.c\
	  time.c\
	  stat.c\
	  sort.c\
	  print_stat.c\
	  get_trace.c\
	  strace.c

OBJ = $(patsubst %.c, $(OBJ_PATH)/%.o, $(SRC))

INCLUDES = includes/ft_strace.h\
		  	includes/syscalls_def.h

all : $(NAME)

$(OBJ_PATH)/%.o : $(addprefix $(PATH_SRC)/, %.c) $(INCLUDES)
	@mkdir -p $(OBJ_PATH)
	@$(CFLAGS) $(OFLAGS) -o $@ -c $<

$(LIB) :
	@$(MKLIB)

$(NAME) : $(LIB) $(OBJ) $(INCLUDES)
	@$(ECHO) "$(GREEN_COLOR)[ $(NAME) objects done ]$(END_COLOR)"
	@$(CFLAGS) -o $(NAME) $(LFLAGS) $(OBJ) $(LFT_FLAGS) $(LFT_FLAGS)
	@$(ECHO) "$(GREEN_COLOR)[ $(NAME) compiled ]$(END_COLOR)"

lib :
	@$(MKLIB)
	@$(MKLIBS)
	@$(ECHO) "$(GREEN_COLOR)[ Libraries compiled ]$(END_COLOR)"

clean :
	@$(ECHO) "$(YELLOW_COLOR)== Deleting libraries objects ==$(END_COLOR)"
	@$(MKLIB) clean
	@$(ECHO) "$(YELLOW_COLOR)== Done ==$(END_COLOR)"
	@rm -f $(OBJ)
	@$(ECHO) "$(BLUE_COLOR)[ $(NAME) objects deleted ]$(END_COLOR)"

fclean : clean
	@$(ECHO) "$(YELLOW_COLOR)== Deleting libraries ==$(END_COLOR)"
	@$(MKLIB) fclean
	@$(ECHO) "$(YELLOW_COLOR)== Done ==$(END_COLOR)"
	@rm -f $(NAME)
	@rm -df $(OBJ_PATH)
	@$(ECHO) "$(PURPLE_COLOR)[ $(NAME) deleted ]$(END_COLOR)"

re : fclean all

.PHONY : fclean re clean all lib
