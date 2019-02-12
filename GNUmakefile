prefix=/usr/local
exec_prefix=$(prefix)
sbindir=$(exec_prefix)/sbin
datadir=$(prefix)/share

PACKAGE=$(shell gcc -E -dM config.h|awk '$$2=="PACKAGE"{gsub(/"/,"");print$$3}')
VERSION=$(shell gcc -E -dM config.h|awk '$$2=="VERSION"{gsub(/"/,"");print$$3}')
URL=$(shell gcc -E -dM config.h|awk '$$2=="CONTACT"{gsub(/"/,"");print$$3}')

PROJECT_ID := $(PACKAGE)-$(VERSION)

CFLAGS=-std=gnu99 -Wall -W -DNDEBUG -g -O
#CFLAGS=-std=gnu99 -Wall -W -g -O0
LDFLAGS=-lcrypto

targets := in.authd $(patsubst %.po,%.mo,$(wildcard *.po))
docs    := README.html COPYING

all: $(targets)

ja.mo: ja.po

in.authd: authd.c config.h
	gcc $(CFLAGS) $(LDFLAGS) -o $@ $<
authd.pot: authd.c


.PHONY: clean
clean:
	$(RM) $(targets) *.po~ *.pot tags TAGS

.PHONY: install
install: $(targets)
	install -d $(sbindir) $(datadir)/doc/$(PACKAGE)
	install in.authd $(sbindir)
	install -m 644 $(docs) $(datadir)/doc/$(PACKAGE)
	for file in *.mo; \
	do dir=$(datadir)/locale/$$(basename $${file} .mo)/LC_MESSAGES; \
	   install -d $${dir}; \
	   install -m 644 $${file} $${dir}/authd.mo; \
	done

%.mo: %.po authd.pot
	msgmerge -U $< authd.pot
	sed -r -i 's|(Project-Id-Version:).*(\\n)|\1 $(PROJECT_ID)\2|' $<
	sed -r -i 's|(Report-Msgid-Bugs-To:).*(\\n)|\1 <$(URL)>\2|' $<
	sed -r -i 's|(Language-Team:).*(\\n)|\1 $(basename $@) <$(URL)>\2|' $<
	msgfmt --statistics --check -o $@ $<

%.pot: %.c
	xgettext --keyword=_ --output=$@ $<
