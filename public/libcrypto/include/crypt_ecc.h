#ifndef __CRYPT_ECC_H
#define __CRYPT_ECC_H

#include <openssl/ec.h>

EC_POINT* qinn_point_add(EC_GROUP *gp, EC_POINT *p1, EC_POINT *p2);

EC_POINT* qinn_point_double(EC_GROUP *gp, EC_POINT *a);

EC_POINT* qinn_point_double_v2(EC_GROUP *gp, EC_POINT *a);


#endif