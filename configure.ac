

AC_INIT
AC_CONFIG_SRCDIR([main.c])

AC_PROG_CC
AC_LANG([C])
AC_PROG_MAKE_SET
AC_PROG_EGREP
AC_SYS_LARGEFILE


AC_ARG_WITH(libuseful, [  --with-libuseful		use system-wide libUseful (default=auto) ], cf_system_libuseful=$withval )

if test "$cf_system_libuseful" != "no"
then
AC_CHECK_HEADER([libUseful-5/libUseful.h], [ AC_CHECK_LIB([Useful-5],GetToken,[cf_have_libUseful5=yes],[cf_have_libUseful5=no]) ])
fi

if test "$cf_system_libuseful" != "no" -a "$cf_have_libUseful5" != "yes"
then
AC_CHECK_HEADER([libUseful-4/libUseful.h], [ AC_CHECK_LIB([Useful-4],GetToken,[cf_have_libUseful4=yes],[cf_have_libUseful4=no]) ])
fi

dnl check for libs that might be needed either by bundled or system-wide libuseful
AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init)
cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_init

dnl New versions of openssl seem to lack EVP_CIPHER_CTX_init, so let's look for another function. I've no idea what's going on with openssl, this is why I use libressl instead.
if test "$cf_have_libcrypto" != "yes"
then
	AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_new)
	cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_new
fi


AC_CHECK_LIB(ssl,SSL_library_init)
cf_have_libssl=$ac_cv_lib_ssl_SSL_library_init

dnl New versions of openssl seem to lack SSL_library_init, so let's look for another function. I've no idea what's going on with openssl, this is why I use libressl instead.
if test "$cf_have_libssl" != "yes"
then
	AC_CHECK_LIB(ssl,OPENSSL_init_ssl)
	cf_have_libssl=$ac_cv_lib_ssl_OPENSSL_init_ssl
fi


AC_CHECK_LIB(z,deflate)


if test "$cf_have_libUseful5" = "yes" -o "$cf_have_libUseful4" = "yes"

then
  AC_SUBST(LIBUSEFUL_BUNDLED,"")

  dnl Default behavior of AC_CHECK_LIB is to add the library to the LIBS variable
  if test "$cf_have_libUseful4" == yes
  then
  echo "installed libUseful-5 found, using that instead of bundled libUseful."
  echo "if you want to use bundled libUseful, force it with --with-libuseful=no"
  AC_CHECK_LIB([Useful-4],GetToken,,)
  else
  echo "installed libUseful-5 found, using that instead of bundled libUseful."
  echo "if you want to use bundled libUseful, force it with --with-libuseful=no"
  AC_CHECK_LIB([Useful-5],GetToken,,)
  fi

else
  echo "no installed libuseful found. Using bundled libUseful."
  AC_SUBST(LIBUSEFUL_BUNDLED,"libUseful/libUseful.a")
  AC_CONFIG_SUBDIRS([libUseful])
fi

AC_PROG_CC 
AC_LANG([C]) 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
m4_warn([obsolete],
[The preprocessor macro `STDC_HEADERS' is obsolete.
  Except in unusual embedded environments, you can safely include all
  ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP
 
AC_SYS_LARGEFILE

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
