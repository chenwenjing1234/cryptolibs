include_directories(${ROOTDIR}/crypto/include)

set(LIBNAME "crypto")
aux_source_directory(. SRC_LIST)
add_library(${LIBNAME} STATIC ${SRC_LIST})