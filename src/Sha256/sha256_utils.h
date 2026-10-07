//
//  sha256_utils.h
//  
//
//  Created by Vincent Dugat on 08/01/2018.
//

#ifndef sha256_utils_h
#define sha256_utils_h
#include "sha256.h"
void sha256ofString(BYTE * str,char hashRes[SHA256_BLOCK_SIZE*2 + 1]);

#endif /* sha256_utils_h */
