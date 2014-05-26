IDIR =../include
CC=gcc

ODIR=obj
LDIR =../lib

LIBS=$(LDIR)/miracl.a -lbsd

CFLAGS=-I$(IDIR) -L $(LDIR)

_DEPS = jdh.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = jdh.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

jdh: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 
