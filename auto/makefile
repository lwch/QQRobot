
cat << END > Makefile

CC=$CC
CFLAGS=$CFLAGS
CINCLUDES=$CINCLUDES
LDFLAGS=$LDFLAGS
LDLIBRARIES=$LDLIBRARIES
TARGET=qqrobot

ALL_OBJS=$ALL_OBJS

all: link

link: \$(ALL_OBJS)
	\$(CC) \$(CFLAGS) \$(CINCLUDES) \$(LDFLAGS) \$(LDLIBRARIES) -o \$(TARGET) \$(ALL_OBJS)

clean:
	rm -fr \$(ALL_OBJS) \$(TARGET)

distclean:
	rm -fr \$(ALL_OBJS) \$(TARGET) Makefile

END

for obj in $ALL_OBJS
do
    file=`echo $obj|sed -e "s/$OBJS_PATH\/\(.*\).o/src\/\1/"`

cat << END >> Makefile

$obj: $file
	\$(CC) \$(CFLAGS) \$(CINCLUDES) -c $< -o \$@

END

done

