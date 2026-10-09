# =============================================================================
#  DIYPG - Makefile
#
#  Arborescence attendue :
#    include/   en-tetes (.h)              src/    sources du projet (.c)
#    test/      main.c, tests.c, test_sha.c
#    build/     fichiers objets (genere)   bin/    executables (genere)
#
#  Cibles :
#    make            compile bin/phase1
#    make test       compile puis lance les tests de la phase 1
#    make overflow   bilan du depassement de capacite (MAX_PRIME)
#    make sha_test   compile et lance test/test_sha.c (SHA-256)
#    make ctrl_c     compile la demo de gestion de Ctrl-C (phase 3)
#    make clean      supprime build/, bin/ et les fichiers de test
# =============================================================================

CC       = gcc
CFLAGS   = -Wall -Wextra -g -O0
CPPFLAGS = -Iinclude -MMD -MP
LDFLAGS  =
LDLIBS   =

BUILD = build
BIN   = bin

# --- sources ----------------------------------------------------------------
# src/*.c uniquement (pas src/Sha256/ : doublon des fichiers sha256 de src/)
SHA_SRC  = src/sha256.c src/sha256_utils.c
# ctrl_c.c a son propre main() : jamais lie avec le reste
NOT_CORE = src/ctrl_c.c $(SHA_SRC)
CORE_SRC = $(filter-out $(NOT_CORE),$(wildcard src/*.c))

PHASE1_SRC = $(CORE_SRC) test/main.c test/tests.c
SHA_TEST_SRC = $(SHA_SRC) test/test_sha.c

obj = $(patsubst %.c,$(BUILD)/%.o,$(1))
PHASE1_OBJ   = $(call obj,$(PHASE1_SRC))
SHA_TEST_OBJ = $(call obj,$(SHA_TEST_SRC))
CTRL_C_OBJ   = $(call obj,src/ctrl_c.c)
DEPS = $(PHASE1_OBJ:.o=.d) $(SHA_TEST_OBJ:.o=.d) $(CTRL_C_OBJ:.o=.d)

.PHONY: all test overflow sha_test ctrl_c clean help
.DEFAULT_GOAL := all

all: $(BIN)/phase1

# --- executables --------------------------------------------------------------
$(BIN)/phase1: $(PHASE1_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/sha_test: $(SHA_TEST_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/ctrl_c: $(CTRL_C_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# --- compilation d'un .c -> .o (build/ reproduit l'arborescence) --------------
$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# --- raccourcis ---------------------------------------------------------------
test: $(BIN)/phase1
	./$(BIN)/phase1 tests

overflow: $(BIN)/phase1
	./$(BIN)/phase1 overflow 30

sha_test: $(BIN)/sha_test
	./$(BIN)/sha_test

ctrl_c: $(BIN)/ctrl_c

clean:
	rm -rf $(BUILD) $(BIN) log.txt test_keys.bin

help:
	@sed -n '4,16p' Makefile

# dependances automatiques (modifier un .h recompile les .c concernes)
-include $(DEPS)
