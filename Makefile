#  DIYPG - Makefile
#
#  Cibles :
#    make              compile bin/diypg (programme principal) et bin/phase1
#    make run          compile et lance l'interprete interactif DIYPG
#    make test         lance les tests de la phase 1
#    make test_conv    lance les tests de conversions base64 / clefs publiques
#    make test_phase2  lance les tests de la phase 2 (GMP & blocs de 4 octets)
#    make test_phase3  lance les tests de la phase 3 (interprete & trousseau)
#    make test_all     lance l'ensemble des suites de tests (phases 1, 2, 3 et conv)
#    make overflow     bilan du depassement de capacite (MAX_PRIME)
#    make sha_test     compile et lance test/test_sha.c (SHA-256)
#    make ctrl_c       compile la demo de gestion de Ctrl-C (phase 3)
#    make clean        supprime build/, bin/ et les fichiers temporaires

CC       = gcc
CFLAGS   = -Wall -Wextra -g -O0
CPPFLAGS = -Iinclude -MMD -MP
LDFLAGS  =
LDLIBS   = -lgmp

BUILD = build
BIN   = bin

# --- sources ---
# src/*.c uniquement (pas src/Sha256/ : doublon des fichiers sha256 de src/)
SHA_SRC  = src/sha256.c src/sha256_utils.c
# ctrl_c.c et main_diypg.c ont leur propre main() : exclus du socle commun CORE_SRC
NOT_CORE = src/ctrl_c.c src/main_diypg.c
CORE_SRC = $(filter-out $(NOT_CORE),$(wildcard src/*.c))

DIYPG_SRC        = $(CORE_SRC) src/main_diypg.c
PHASE1_SRC       = $(CORE_SRC) test/main.c test/tests.c
TEST_CONV_SRC    = $(CORE_SRC) test/tests_conversions.c
TEST_PHASE2_SRC  = $(CORE_SRC) test/tests_phase2.c
TEST_PHASE3_SRC  = $(CORE_SRC) test/tests_phase3.c
SHA_TEST_SRC     = $(SHA_SRC) test/test_sha.c

obj = $(patsubst %.c,$(BUILD)/%.o,$(1))
DIYPG_OBJ        = $(call obj,$(DIYPG_SRC))
PHASE1_OBJ       = $(call obj,$(PHASE1_SRC))
TEST_CONV_OBJ    = $(call obj,$(TEST_CONV_SRC))
TEST_PHASE2_OBJ  = $(call obj,$(TEST_PHASE2_SRC))
TEST_PHASE3_OBJ  = $(call obj,$(TEST_PHASE3_SRC))
SHA_TEST_OBJ     = $(call obj,$(SHA_TEST_SRC))
CTRL_C_OBJ       = $(call obj,src/ctrl_c.c)

DEPS = $(DIYPG_OBJ:.o=.d) $(PHASE1_OBJ:.o=.d) $(TEST_CONV_OBJ:.o=.d) \
       $(TEST_PHASE2_OBJ:.o=.d) $(TEST_PHASE3_OBJ:.o=.d) \
       $(SHA_TEST_OBJ:.o=.d) $(CTRL_C_OBJ:.o=.d)

# On masque uniquement les warnings des fichiers fournis :
PROVIDED_OBJ = $(call obj,src/rsa_tools.c src/bezout.c src/other_base64.c src/int2char.c)
$(PROVIDED_OBJ): CFLAGS += -Wno-format -Wno-sign-compare -Wno-char-subscripts

.PHONY: all run test test_conv test_phase2 test_phase3 test_all overflow sha_test ctrl_c clean help
.DEFAULT_GOAL := all

all: $(BIN)/diypg $(BIN)/phase1

# --- executables ---
$(BIN)/diypg: $(DIYPG_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/phase1: $(PHASE1_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/tests_conversions: $(TEST_CONV_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/tests_phase2: $(TEST_PHASE2_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/tests_phase3: $(TEST_PHASE3_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/sha_test: $(SHA_TEST_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/ctrl_c: $(CTRL_C_OBJ)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# --- compilation d'un .c -> .o (build/ reproduit l'arborescence) ---
$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# --- raccourcis d'execution et de tests ---
run: $(BIN)/diypg
	./$(BIN)/diypg

test: $(BIN)/phase1
	./$(BIN)/phase1 tests

test_conv: $(BIN)/tests_conversions
	./$(BIN)/tests_conversions

test_phase2: $(BIN)/tests_phase2
	./$(BIN)/tests_phase2

test_phase3: $(BIN)/tests_phase3
	./$(BIN)/tests_phase3

test_all: test test_conv test_phase2 test_phase3

overflow: $(BIN)/phase1
	./$(BIN)/phase1 overflow 30

sha_test: $(BIN)/sha_test
	./$(BIN)/sha_test

ctrl_c: $(BIN)/ctrl_c

clean:
	rm -rf $(BUILD) $(BIN) log.txt test_keys.bin trousseau.diypg

help:
	@sed -n '4,15p' Makefile

# dependances automatiques (modifier un .h recompile les .c concernes)
-include $(DEPS)