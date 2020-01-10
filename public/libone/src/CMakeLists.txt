include_directories(${ROOTDIR}/libone/include)

set(LIBNAME "libone")
aux_source_directory(. SRC_LIST)
add_library(${LIBNAME} STATIC ${SRC_LIST})

#将${LIBNAME}工程组织到public目录下 
set_target_properties(${LIBNAME} PROPERTIES FOLDER "public")