
include_directories(${ROOTDIR}/crypto/include)


set(EXENAME "cryptotest")
set(DEPENDLIBS crypto)
aux_source_directory(. SRC_LIST)
add_executable(${EXENAME} ${SRC_LIST})

target_link_libraries(${EXENAME} ${DEPENDLIBS})

set_target_properties(${LIBNAME} PROPERTIES FOLDER "test")