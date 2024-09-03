# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Read README.cmake before using this.

# CMAKE_MINIMUM_REQUIRED should be the first directive in the file:
# https://cmake.org/cmake/help/latest/command/cmake_minimum_required.html
CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(APR-Util C)

# Enable support for MSVC runtime library selection by abstraction
# if supported by CMake.
IF(POLICY CMP0091)
  CMAKE_POLICY(SET CMP0091 NEW)
ENDIF()

FIND_PACKAGE(APR REQUIRED)
FIND_PACKAGE(EXPAT)
FIND_PACKAGE(LibXml2)
FIND_PACKAGE(OpenSSL)
FIND_PACKAGE(SQLite3)

IF(NOT EXPAT_FOUND AND NOT LIBXML2_FOUND)
  MESSAGE(FATAL_ERROR "Either Expat or LibXml2 is required, but neither was found")
ENDIF()

IF(EXPAT_FOUND)
  OPTION(APU_USE_EXPAT      "Use Expat"                    ON)
  OPTION(APU_USE_LIBXML2    "Use LibXml2"                  OFF)
ELSE()
  OPTION(APU_USE_EXPAT      "Use Expat"                    OFF)
  OPTION(APU_USE_LIBXML2    "Use LibXml2"                  ON)
ENDIF()

OPTION(APU_BUILD_SHARED     "Build shared libraries"                    ON)
OPTION(APU_BUILD_STATIC     "Build static libraries"                    ON)
OPTION(APU_DSO_BUILD        "Use DSO build of modular components"       ON)
OPTION(APU_HAVE_CRYPTO      "Crypto support"                            OFF)
OPTION(APU_HAVE_ODBC        "Build ODBC DBD driver"                     ON)
OPTION(APU_HAVE_SQLITE3     "Build SQLite3 DBD driver"                  OFF)
OPTION(APR_HAS_LDAP         "LDAP support"                              ON)
OPTION(INSTALL_PDB          "Install .pdb files (if generated)"         ON)
OPTION(APR_BUILD_TESTAPR    "Build the test suite"                      OFF)
OPTION(TEST_STATIC_LIBS     "Test programs use APR static libraries instead of shared libraries?" OFF)
SET(LIBXML2_ICONV_INCLUDE_DIR   ""
    CACHE STRING "Directory with iconv include files for libxml2")
SET(LIBXML2_ICONV_LIBRARIES     ""
    CACHE STRING "iconv libraries to link with for libxml2")

IF(NOT APU_BUILD_SHARED AND NOT APU_BUILD_STATIC)
  MESSAGE(FATAL_ERROR "Both APU_BUILD_SHARED and APU_BUILD_STATIC have been disabled")
ENDIF()

IF(NOT APU_BUILD_STATIC AND TEST_STATIC_LIBS)
  MESSAGE(FATAL_ERROR "APU_BUILD_STATIC have been disabled, but TEST_STATIC_LIBS is enabled")
ENDIF()

IF(NOT APU_USE_EXPAT AND NOT APU_USE_LIBXML2)
  MESSAGE(FATAL_ERROR "Either Expat or LibXml2 must be selected")
ENDIF()
IF(APU_USE_EXPAT AND APU_USE_LIBXML2)
  MESSAGE(FATAL_ERROR "Only one of Expat and LibXml2 can be selected")
ENDIF()

IF(APU_DSO_BUILD AND NOT APU_BUILD_SHARED)
  MESSAGE(FATAL_ERROR "APU_DSO_BUILD requires APU_BUILD_SHARED.")
ENDIF()

IF(APU_HAVE_CRYPTO)
IF(NOT OPENSSL_FOUND)
  MESSAGE(FATAL_ERROR "OpenSSL is the only supported crypto implementation, and it wasn't found!")
ENDIF()
ENDIF()

IF(APU_HAVE_SQLITE3)
IF(NOT SQLite3_FOUND)
  MESSAGE(FATAL_ERROR "SQLite3 wasn't found!")
ENDIF()
ENDIF()

# create 1-or-0 representation of feature tests for apu.h

SET(apu_have_apr_iconv_10 0) # not yet implemented

SET(LDAP_LIBRARIES)
IF(APR_HAS_LDAP)
  SET(LDAP_LIBRARIES wldap32)
ENDIF()

CONFIGURE_FILE(include/apu.hwc
              ${PROJECT_BINARY_DIR}/apu.h)
CONFIGURE_FILE(include/apr_ldap.hwc
              ${PROJECT_BINARY_DIR}/apr_ldap.h)
CONFIGURE_FILE(include/private/apu_config.hwc
               ${PROJECT_BINARY_DIR}/apu_config.h)
CONFIGURE_FILE(include/private/apu_select_dbm.hw
               ${PROJECT_BINARY_DIR}/apu_select_dbm.h
               COPYONLY)
CONFIGURE_FILE(include/apu_want.hw
               ${PROJECT_BINARY_DIR}/apu_want.h
               COPYONLY)

IF(APU_USE_EXPAT)
  SET(XMLLIB_INCLUDE_DIR ${EXPAT_INCLUDE_DIRS})
  SET(XMLLIB_LIBRARIES   ${EXPAT_LIBRARIES})
ELSE()
  SET(XMLLIB_INCLUDE_DIR "${LIBXML2_INCLUDE_DIR};${LIBXML2_ICONV_INCLUDE_DIR}")
  SET(XMLLIB_LIBRARIES   "${LIBXML2_LIBRARIES};${LIBXML2_ICONV_LIBRARIES}")
ENDIF()


# Generated .h files are stored in PROJECT_BINARY_DIR, not the
# source tree.
#
# BROKEN: not searching PROJECT_BINARY_DIR first, so you have to
#         manually delete apu.h in PROJECT_SOURCE_DIR/include if
#         you've generated apu.h before using a different build

SET(APR_INCLUDE_DIRECTORIES
  ${PROJECT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/include/private
  ${APR_INCLUDE_DIR}
)

INCLUDE_DIRECTORIES(${APR_INCLUDE_DIRECTORIES} ${XMLLIB_INCLUDE_DIR})

SET(APR_PUBLIC_HEADERS_STATIC
  include/apr_anylock.h
  include/apr_base64.h
  include/apr_buckets.h
  include/apr_buffer.h
  include/apr_crypto.h
  include/apr_date.h
  include/apr_dbd.h
  include/apr_dbm.h
  include/apr_hooks.h
  include/apr_jose.h
  include/apr_json.h
  include/apr_ldap_init.h
  include/apr_ldap_option.h
  include/apr_ldap_rebind.h
  include/apr_ldap_url.h
  include/apr_md4.h
  include/apr_md5.h
  include/apr_memcache.h
  include/apr_optional.h
  include/apr_optional_hooks.h
  include/apr_queue.h
  include/apr_redis.h
  include/apr_reslist.h
  include/apr_rmm.h
  include/apr_sdbm.h
  include/apr_sha1.h
  include/apr_siphash.h
  include/apr_strmatch.h
  include/apr_thread_pool.h
  include/apr_uri.h
  include/apr_uuid.h
  include/apr_xlate.h
  include/apr_xml.h
  include/apu_errno.h
  include/apu_version.h
)

# apu_config.h and apu_select_dbm.h are private
SET(APR_PUBLIC_HEADERS_GENERATED
  ${PROJECT_BINARY_DIR}/apu.h
  ${PROJECT_BINARY_DIR}/apr_ldap.h
  ${PROJECT_BINARY_DIR}/apu_want.h
)

SET(APR_SOURCES
  buckets/apr_brigade.c
  buckets/apr_buckets.c
  buckets/apr_buckets_alloc.c
  buckets/apr_buckets_eos.c
  buckets/apr_buckets_file.c
  buckets/apr_buckets_flush.c
  buckets/apr_buckets_heap.c
  buckets/apr_buckets_mmap.c
  buckets/apr_buckets_pipe.c
  buckets/apr_buckets_pool.c
  buckets/apr_buckets_refcount.c
  buckets/apr_buckets_simple.c
  buckets/apr_buckets_socket.c
  buffer/apr_buffer.c
  crypto/apr_crypto.c
  crypto/apr_crypto_prng.c
  crypto/apr_md4.c
  crypto/apr_md5.c
  crypto/apr_passwd.c
  crypto/apr_sha1.c
  crypto/apr_siphash.c
  crypto/crypt_blowfish.c
  crypto/getuuid.c
  crypto/uuid.c
  dbd/apr_dbd.c
  dbm/apr_dbm.c
  dbm/apr_dbm_sdbm.c
  dbm/sdbm/sdbm.c
  dbm/sdbm/sdbm_hash.c
  dbm/sdbm/sdbm_lock.c
  dbm/sdbm/sdbm_pair.c
  encoding/apr_base64.c
  hooks/apr_hooks.c
  jose/apr_jose.c
  jose/apr_jose_decode.c
  jose/apr_jose_encode.c
  json/apr_json.c
  json/apr_json_decode.c
  json/apr_json_encode.c
  memcache/apr_memcache.c
  misc/apr_date.c
  misc/apr_error.c
  misc/apr_queue.c
  misc/apr_reslist.c
  misc/apr_rmm.c
  misc/apr_thread_pool.c
  misc/apu_dso.c
  misc/apu_version.c
  redis/apr_redis.c
  strmatch/apr_strmatch.c
  uri/apr_uri.c
  xlate/xlate.c
  xml/apr_xml.c
  xml/apr_xml_expat.c
  xml/apr_xml_libxml2.c
)

IF(APR_HAS_LDAP)
  SET(APR_SOURCES ${APR_SOURCES} ldap/apr_ldap_stub.c ldap/apr_ldap_url.c)
ENDIF()

# Sources and libraries for APU builtin drivers. Used when APU_DSO_BUILD=OFF.
SET(APU_EXTRA_SOURCES)
SET(APU_EXTRA_LIBRARIES)
SET(APU_EXTRA_INCLUDE_DIRECTORIES)

SET(APR_TEST_SUITES
  testbuckets
  testbuffer
  testcrypto
  testdate
  testdbd
  testdbm
  testjson
  testjose
  testldap
  testmd4
  testmd5
  testmemcache
  testpass
  testqueue
  testredis
  testreslist
  testrmm
  testsiphash
  teststrmatch
  testuri
  testuuid
  testxlate
  testxml
)

SET(install_targets)
SET(install_bin_pdb)
SET(dbd_drivers)

IF (MSVC)
  # Ignore Microsoft's interpretation of secure development
  # and the POSIX string handling API
  ADD_COMPILE_DEFINITIONS(_CRT_SECURE_NO_DEPRECATE _CRT_NONSTDC_NO_WARNINGS)
ENDIF()

IF(NOT APU_DSO_BUILD AND APU_HAVE_CRYPTO)
  IF(NOT OPENSSL_FOUND)
    MESSAGE(FATAL_ERROR "Only OpenSSL-based crypto is currently implemented in the cmake build")
  ENDIF()

  LIST(APPEND APU_EXTRA_SOURCES crypto/apr_crypto_openssl.c)
  LIST(APPEND APU_EXTRA_LIBRARIES ${OPENSSL_LIBRARIES})
  LIST(APPEND APU_EXTRA_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
ENDIF()

IF(NOT APU_DSO_BUILD AND APU_HAVE_ODBC)
  LIST(APPEND dbd_drivers odbc)

  LIST(APPEND APU_EXTRA_SOURCES dbd/apr_dbd_odbc.c)
  LIST(APPEND APU_EXTRA_LIBRARIES odbc32 odbccp32)
ENDIF()

IF(NOT APU_DSO_BUILD AND APU_HAVE_SQLITE3)
  LIST(APPEND dbd_drivers sqlite3)

  LIST(APPEND APU_EXTRA_SOURCES dbd/apr_dbd_sqlite3.c)
  LIST(APPEND APU_EXTRA_LIBRARIES ${SQLite3_LIBRARIES})
ENDIF()

# libaprutil-1 is shared, aprutil-1 is static
IF(APU_BUILD_SHARED)
  ADD_LIBRARY(libaprutil-1 SHARED ${APR_SOURCES} ${APU_EXTRA_SOURCES} ${APR_PUBLIC_HEADERS_GENERATED} libaprutil.rc)
  SET(install_targets ${install_targets} libaprutil-1)
  SET(install_bin_pdb ${install_bin_pdb} ${PROJECT_BINARY_DIR}/libaprutil-1.pdb)
  TARGET_LINK_LIBRARIES(libaprutil-1
                        PRIVATE apr::libapr-1 ${XMLLIB_LIBRARIES} ${APU_EXTRA_LIBRARIES})
  TARGET_INCLUDE_DIRECTORIES(libaprutil-1
                             PRIVATE ${APU_EXTRA_INCLUDE_DIRECTORIES})
  TARGET_COMPILE_DEFINITIONS(libaprutil-1
                             PRIVATE "APU_DECLARE_EXPORT;XML_STATIC"
                             INTERFACE "APU_DECLARE_IMPORT")
ENDIF()

IF(APU_BUILD_STATIC)
  ADD_LIBRARY(aprutil-1 STATIC ${APR_SOURCES} ${APU_EXTRA_SOURCES} ${APR_PUBLIC_HEADERS_GENERATED})
  SET(install_targets ${install_targets} aprutil-1)
  TARGET_LINK_LIBRARIES(aprutil-1
                        PRIVATE apr::apr-1 ${XMLLIB_LIBRARIES} ${APU_EXTRA_LIBRARIES})
  TARGET_INCLUDE_DIRECTORIES(aprutil-1
                             PRIVATE ${APU_EXTRA_INCLUDE_DIRECTORIES})
  TARGET_COMPILE_DEFINITIONS(aprutil-1
                             PRIVATE "APU_DECLARE_STATIC;XML_STATIC"
                             INTERFACE "APU_DECLARE_STATIC")
ENDIF()

IF(APU_DSO_BUILD AND APU_HAVE_CRYPTO)
  IF(NOT OPENSSL_FOUND)
    MESSAGE(FATAL_ERROR "Only OpenSSL-based crypto is currently implemented in the cmake build")
  ENDIF()
  ADD_LIBRARY(apr_crypto_openssl-1 SHARED crypto/apr_crypto_openssl.c libaprutil.rc)
  SET(install_targets ${install_targets} apr_crypto_openssl-1)
  SET(install_bin_pdb ${install_bin_pdb} ${PROJECT_BINARY_DIR}/apr_crypto_openssl-1.pdb)
  TARGET_INCLUDE_DIRECTORIES(apr_crypto_openssl-1
                             PRIVATE "${OPENSSL_INCLUDE_DIR}")
  TARGET_COMPILE_DEFINITIONS(apr_crypto_openssl-1
                             PRIVATE "DLL_NAME=apr_crypto_openssl")
  TARGET_LINK_LIBRARIES(apr_crypto_openssl-1
                        PRIVATE libaprutil-1 apr::libapr-1 ${OPENSSL_LIBRARIES})
ENDIF()

IF(APU_DSO_BUILD AND APU_HAVE_ODBC)
  ADD_LIBRARY(apr_dbd_odbc-1 SHARED dbd/apr_dbd_odbc.c libaprutil.rc)
  SET(install_targets ${install_targets} apr_dbd_odbc-1)
  SET(install_bin_pdb ${install_bin_pdb} ${PROJECT_BINARY_DIR}/apr_dbd_odbc-1.pdb)
  SET(dbd_drivers ${dbd_drivers} odbc)
  TARGET_LINK_LIBRARIES(apr_dbd_odbc-1
                        PRIVATE libaprutil-1 apr::libapr-1 odbc32 odbccp32)
  SET_PROPERTY(TARGET apr_dbd_odbc-1 APPEND PROPERTY LINK_FLAGS /export:apr_dbd_odbc_driver)
  TARGET_COMPILE_DEFINITIONS(apr_dbd_odbc-1
                             PRIVATE "DLL_NAME=apr_dbd_odbc")
ENDIF()

IF(APU_DSO_BUILD AND APR_HAS_LDAP)
  ADD_LIBRARY(apr_ldap-1 SHARED ldap/apr_ldap_init.c ldap/apr_ldap_option.c 
              ldap/apr_ldap_rebind.c libaprutil.rc)
  SET(install_targets ${install_targets} apr_ldap-1)
  SET(install_bin_pdb ${install_bin_pdb} ${PROJECT_BINARY_DIR}/apr_ldap-1.pdb)
  TARGET_LINK_LIBRARIES(apr_ldap-1 libaprutil-1
                        PRIVATE apr::libapr-1 ${LDAP_LIBRARIES})
  TARGET_COMPILE_DEFINITIONS(apr_ldap-1
                             PRIVATE "DLL_NAME=apr_ldap")
  SET(apr_ldap_libraries apr_ldap-1)
ELSE()
  SET(apr_ldap_libraries)
ENDIF()

IF(APU_DSO_BUILD AND APU_HAVE_SQLITE3)
  ADD_LIBRARY(apr_dbd_sqlite3-1 SHARED dbd/apr_dbd_sqlite3.c libaprutil.rc)
  SET(install_targets ${install_targets} apr_dbd_sqlite3-1)
  SET(install_bin_pdb ${install_bin_pdb} ${PROJECT_BINARY_DIR}/apr_dbd_sqlite3-1.pdb)
  SET(dbd_drivers ${dbd_drivers} sqlite3)
  TARGET_INCLUDE_DIRECTORIES(apr_dbd_sqlite3-1
                             PRIVATE "${SQLite3_INCLUDE_DIRS}")
  TARGET_LINK_LIBRARIES(apr_dbd_sqlite3-1
                        PRIVATE libaprutil-1 apr::libapr-1 ${SQLite3_LIBRARIES})
  SET_PROPERTY(TARGET apr_dbd_sqlite3-1 APPEND PROPERTY LINK_FLAGS /export:apr_dbd_sqlite3_driver)
  TARGET_COMPILE_DEFINITIONS(apr_dbd_sqlite3-1
                             PRIVATE "DLL_NAME=apr_dbd_sqlite3-1")
ENDIF()

IF(APR_BUILD_TESTAPR)
  ENABLE_TESTING()
  # Create a "check" target that displays test program output to the console.
  ADD_CUSTOM_TARGET(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)

  # copy data files to build directory so that we can run programs from there
  EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory 
                  ${PROJECT_BINARY_DIR}/data)
  EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E copy_if_different 
                  ${PROJECT_SOURCE_DIR}/test/data/billion-laughs.xml
                  ${PROJECT_BINARY_DIR}/data/billion-laughs.xml)

  IF(TEST_STATIC_LIBS)
    SET(whichapr    "apr::apr-1;aprutil-1")
  ELSE()
    SET(whichapr    "apr::libapr-1;libaprutil-1")
  ENDIF()

  SET (APR_TEST_SOURCES
    test/abts.c
    test/testutil.c
    )

  FOREACH(testsuite ${APR_TEST_SUITES})
    LIST(APPEND APR_TEST_SOURCES test/${testsuite}.c)
  ENDFOREACH()

  ADD_EXECUTABLE(testall ${APR_TEST_SOURCES})
  TARGET_LINK_LIBRARIES(testall ${whichapr})
  TARGET_COMPILE_DEFINITIONS(testall PRIVATE "BINPATH=$<TARGET_FILE_DIR:testall>")

  FOREACH(test ${APR_TEST_SUITES})
    ADD_TEST(NAME ${test} COMMAND testall -v ${test})
  ENDFOREACH()

  ADD_EXECUTABLE(dbd test/dbd.c)
  TARGET_LINK_LIBRARIES(dbd ${whichapr})

  # dbd is run multiple times with different parameters.
  FOREACH(somedbd ${dbd_drivers})
    ADD_TEST(NAME dbd-${somedbd} COMMAND dbd ${somedbd})
  ENDFOREACH()

  ADD_EXECUTABLE(memcachedmock test/memcachedmock.c)
  TARGET_LINK_LIBRARIES(memcachedmock ${whichapr})

  ADD_DEPENDENCIES(testall memcachedmock)
ENDIF (APR_BUILD_TESTAPR)

# Installation

INSTALL(TARGETS ${install_targets}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
       )

IF(INSTALL_PDB)
  INSTALL(FILES ${install_bin_pdb}
          DESTINATION bin
          CONFIGURATIONS RelWithDebInfo Debug)
ENDIF()

INSTALL(FILES ${APR_PUBLIC_HEADERS_STATIC} ${APR_PUBLIC_HEADERS_GENERATED} DESTINATION include)

STRING(TOUPPER "${CMAKE_BUILD_TYPE}" buildtype)
MESSAGE(STATUS "")
MESSAGE(STATUS "")
MESSAGE(STATUS "APR-Util configuration summary:")
MESSAGE(STATUS "")
MESSAGE(STATUS "  Build type ...................... : ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "  Build shared libs ............... : ${APU_BUILD_SHARED}")
MESSAGE(STATUS "  Build static libs ............... : ${APU_BUILD_STATIC}")
MESSAGE(STATUS "  Install .pdb (if available)...... : ${INSTALL_PDB}")
MESSAGE(STATUS "  Install prefix .................. : ${CMAKE_INSTALL_PREFIX}")
MESSAGE(STATUS "  C compiler ...................... : ${CMAKE_C_COMPILER}")
MESSAGE(STATUS "  DBD ODBC driver ................. : ${APU_HAVE_ODBC}")
MESSAGE(STATUS "  DBD SQLite3 driver .............. : ${APU_HAVE_SQLITE3}")
MESSAGE(STATUS "  APU_HAVE_CRYPTO ................. : ${APU_HAVE_CRYPTO}")
MESSAGE(STATUS "  APR_HAS_LDAP .................... : ${APR_HAS_LDAP}")
MESSAGE(STATUS "  Use Expat ....................... : ${APU_USE_EXPAT}")
MESSAGE(STATUS "  Use LibXml2 ..................... : ${APU_USE_LIBXML2}")
MESSAGE(STATUS "  Build test suite ................ : ${APR_BUILD_TESTAPR}")
IF(TEST_STATIC_LIBS)
MESSAGE(STATUS "    (testing static libraries)")
ELSE()
MESSAGE(STATUS "    (testing dynamic libraries)")
ENDIF()
