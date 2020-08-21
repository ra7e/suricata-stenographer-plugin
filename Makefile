SRCS :=		template.c \
			util-stenographer.c

# This needs to point to the Suricata includes.

CPPFLAGS +=	-DSURICATA_PLUGIN -I.

LDLIBS += -lcurl

all:
	$(CC) -fPIC $(CPPFLAGS) -o eve-filetype.so -shared $(SRCS) $(LDLIBS)

clean:
	rm -f *.so *~
