CC      := gcc
CSTD    := -std=c23
CPPFLAGS:= -D_GNU_SOURCE
WARN    := -Wall -Wextra -Wshadow
OPT     := -O2
CFLAGS  := $(CSTD) $(WARN) $(OPT) -g
LDLIBS  := -lcrypto

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
DEP := $(OBJ:.o=.d)
BIN := cifrar

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c $< -o $@

-include $(DEP)

run: $(BIN)
	./$(BIN)

test: $(BIN)
	@echo "== selftest criptográfico =="
	./$(BIN) --selftest
	@echo "== prueba de seguridad (ruta insegura) =="
	./$(BIN) --prueba-inseguro
	@echo "== prueba end-to-end =="
	bash tests/smoke.sh ./$(BIN)

sanitize: $(SRC)
	$(CC) $(CSTD) $(WARN) -O1 -g -fsanitize=address,undefined $(CPPFLAGS) \
		-o $(BIN)-asan $(SRC) $(LDLIBS)

clean:
	rm -f $(OBJ) $(DEP) $(BIN) $(BIN)-asan

.PHONY: all run test sanitize clean
