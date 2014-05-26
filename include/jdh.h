#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "miracl.h"

#define MAXBUF         1024
#define NSIZE          128
#define XSIZE          64
#define DIGEST         32

#define AESMODE        MR_PCFB1  /* MR_OFB1 */
#define ERR_AES_INIT   "\nFailed to initialize AES struct"
