
rm -f Makefile.tmp
FLAG=0
ALL_OBJS=
for obj in $ALL_FILES
do
    if [ $FLAG = 0 ]; then
        SRC=$obj
        FLAG=1
    else
        ALL_OBJS="$ALL_OBJS $obj"
        FLAG=0
cat << END >> Makefile.tmp
$obj: $SRC
	\$(CC) \$(CFLAGS) \$(CINCLUDES) -c $< -o \$@

END
    fi
done

cat << END > Makefile

CC=$CC
CFLAGS=$CFLAGS
CINCLUDES=$CINCLUDES
LDFLAGS=$LDFLAGS
LDLIBRARIES=$LDLIBRARIES
TARGET=qqrobot

ALL_OBJS=$ALL_OBJS $OBJS_PATH/auto_module.c.o

all: link

link: \$(ALL_OBJS)
	\$(CC) \$(CFLAGS) \$(CINCLUDES) -o \$(TARGET) \$(ALL_OBJS)  \$(LDFLAGS) \$(LDLIBRARIES)

clean:
	rm -fr \$(ALL_OBJS) \$(TARGET)

distclean:
	rm -fr \$(ALL_OBJS) \$(TARGET) Makefile

$OBJS_PATH/auto_module.c.o: $OBJS_PATH/auto_module.c
	\$(CC) \$(CFLAGS) \$(CINCLUDES) -c $< -o \$@

END

cat Makefile.tmp >> Makefile
rm Makefile.tmp

