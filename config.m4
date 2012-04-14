dnl $Id: config.m4 287913 2012-03-28 13:10:35Z JohnOhl $

PHP_ARG_WITH(libevent2, for libevent2 support,
[  --with-libevent2             Include libevent2 support])

if test "$PHP_LIBEVENT2" != "no"; then
  SEARCH_PATH="/usr /usr/local"
  SEARCH_FOR="/include/event2/event.h"

  if test "$PHP_LIBEVENT2" = "yes"; then
    AC_MSG_CHECKING([for libevent2 headers in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        LIBEVENT2_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  else
    AC_MSG_CHECKING([for libevent2 headers in $PHP_LIBEVENT2])
    if test -r $PHP_LIBEVENT2/$SEARCH_FOR; then
      LIBEVENT2_DIR=$PHP_LIBEVENT2
      AC_MSG_RESULT([found])
    fi
  fi

  if test -z "$LIBEVENT2_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Cannot find libevent2 headers])
  fi

  PHP_ADD_INCLUDE($LIBEVENT2_DIR/include)

  LIBNAME=event
  LIBSYMBOL=event_base_new

  if test "x$PHP_LIBDIR" = "x"; then
    PHP_LIBDIR=lib
  fi

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $LIBEVENT2_DIR/$PHP_LIBDIR, LIBEVENT2_SHARED_LIBADD)
  ],[
    AC_MSG_ERROR([wrong libevent2 version {2.0.+ is required} or lib not found])
  ],[
    -L$LIBEVENT2_DIR/$PHP_LIBDIR 
  ])

  PHP_ADD_EXTENSION_DEP(libevent2, sockets, true)
  PHP_SUBST(LIBEVENT2_SHARED_LIBADD)
  PHP_NEW_EXTENSION(libevent2, libevent2.c, $ext_shared)
fi
