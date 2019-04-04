

AC_INIT([main.c])



AC_ARG_WITH(libuseful, [  --with-libuseful		use system-wide libUseful (default=auto) ], cf_system_libuseful=$withval )

if test "$cf_system_libuseful" != "no"
then
AC_CHECK_LIB(Useful,GetToken,[cf_have_libUseful=yes],[cf_have_libUseful=no])
fi

if test "$cf_have_libUseful" = "yes"
then
  echo "installed libUseful found, using that instead of bundled libUseful."
  echo "if you want to use bundled libUseful, force it with --with-libuseful=no"
  AC_SUBST(LIBUSEFUL_BUNDLED,"")
  dnl Default behavior of AC_CHECK_LIB is to add the library to the LIBS variable
  AC_CHECK_LIB(Useful,GetToken,,)

	dnl openssl isn't really needed, but if it exists and we're using a system-wide libUseful, then that will
	dnl likely be linked against it
	AC_CHECK_LIB(ssl,SSL_library_init,,)
	AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
else
  AC_SUBST(LIBUSEFUL_BUNDLED,"libUseful/libUseful.a")
  AC_CONFIG_SUBDIRS([libUseful])
fi

AC_PROG_CC 
AC_LANG_C 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
AC_HEADER_STDC 
AC_SYS_LARGEFILE

AC_OUTPUT(Makefile)
