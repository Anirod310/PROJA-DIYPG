#include "../rsa_common_header.h"
// conversion 4 octets en un int
uint32_t convert_4byte2int(uint8_t *b){
  // ordre little endian
  uint32_t nombre = b[3]<<24 | b[2]<<16 | b[1]<<8 | b[0];
	//uint nombre = b[0]<<24 | b[1]<<16 | b[2]<<8 | b[3]; big endian
  return nombre;
}

// conversion 1 int en 4 octets
void convertInt2uchar(uint32_t nb,uint8_t *tab4bytes){
 // convert from an unsigned long int to a 4-byte array
 	tab4bytes[3] = (int)((nb >> 24) & 0xFF) ;
 	tab4bytes[2] = (int)((nb >> 16) & 0xFF) ;
 	tab4bytes[1] = (int)((nb >> 8) & 0XFF);
 	tab4bytes[0] = (int)((nb & 0XFF));
}
