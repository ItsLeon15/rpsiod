CC ?= gcc
CFLAGS ?= -O3 -flto -march=native -fno-plt -g -pthread
WARNINGS := -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wstrict-prototypes
CPPFLAGS := -D_GNU_SOURCE
LDFLAGS ?=
LDLIBS ?=
RPSIOD_LDLIBS := -pthread -lssl -lcrypto -ldl -lnghttp2 -lngtcp2 -lnghttp3 -lngtcp2_crypto_ossl

BIN := build/rpsiod
OBJDIR := build/obj
SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SRC))

.PHONY: all clean install uninstall check

all: $(BIN)

$(BIN): $(OBJ)
	install -d build
	$(CC) $(CFLAGS) $(WARNINGS) -o $@ $(OBJ) $(LDFLAGS) $(LDLIBS) $(RPSIOD_LDLIBS)

$(OBJDIR)/%.o: src/%.c src/*.h
	install -d $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -c $< -o $@

check: all
	./$(BIN) config-check --server examples/server.yml --sites examples/sites.yml

install: all
	getent group rpsiod >/dev/null || groupadd --system rpsiod
	id -u rpsiod >/dev/null 2>&1 || useradd --system --gid rpsiod --no-create-home --home-dir /var/lib/rpsiod --shell /usr/sbin/nologin rpsiod
	install -d /usr/local/sbin
	rm -f /usr/local/sbin/rpsiod
	install -m 0755 $(BIN) /usr/local/sbin/rpsiod
	install -d -m 0755 /etc/rpsiod
	install -d -m 0750 /var/log/rpsiod /var/cache/rpsiod /run/rpsiod
	install -d -m 0700 /var/lib/rpsiod/ssl
	install -d -m 0755 /var/www/rpsiod-example /var/www/rpsiod-errors
	install -m 0644 examples/www/example.com/index.html /var/www/rpsiod-example/index.html
	install -m 0644 www/rpsiod-errors/404.html /var/www/rpsiod-errors/404.html
	install -m 0644 www/rpsiod-errors/500.html /var/www/rpsiod-errors/500.html
	install -m 0644 www/rpsiod-errors/maintenance.html /var/www/rpsiod-errors/maintenance.html
	test -f /etc/rpsiod/server.yml || install -m 0644 config/server.yml /etc/rpsiod/server.yml
	test -f /etc/rpsiod/sites.yml || install -m 0644 config/sites.yml /etc/rpsiod/sites.yml
	rm -f /etc/systemd/system/rpsiod.service
	install -m 0644 rpsiod.service /etc/systemd/system/rpsiod.service

uninstall:
	systemctl disable --now rpsiod.service 2>/dev/null || true
	rm -f /etc/systemd/system/rpsiod.service /usr/local/sbin/rpsiod
	systemctl daemon-reload 2>/dev/null || true
	@if [ "$${PURGE:-0}" = "1" ]; then \
		rm -rf /etc/rpsiod /var/log/rpsiod /var/cache/rpsiod /var/lib/rpsiod /run/rpsiod /var/www/rpsiod-example /var/www/rpsiod-errors; \
		echo "rpsiod service, binary, configs, logs, cache, state, runtime directories, and example web roots removed"; \
	else \
		echo "rpsiod service and binary removed; configs and runtime data were left in place"; \
		echo "run 'make uninstall PURGE=1' to remove /etc/rpsiod and rpsiod runtime data"; \
	fi

clean:
	rm -rf build src/*.o rpsiod
