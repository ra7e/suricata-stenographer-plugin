SRCS :=		template.c \
			util-stenographer.c

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

# This needs to point to the Suricata includes.

CPPFLAGS +=	-DSURICATA_PLUGIN -I.

LDLIBS += -lcurl

all:
	$(CC) -fPIC $(CPPFLAGS) -o eve-stenographer.so -shared $(SRCS) $(LDLIBS)

clean:
	rm -f *.so *~

install: eve-stenographer.so
	install -d $(PREFIX)/lib/
	install -m 644 eve-stenographer.so $(PREFIX)/lib/
