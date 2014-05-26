/* 

  Diffie Hellman Key Exchange (Slow) Demo Implementation
  JB Gericke
  julian@sasquatchpie.co.za
*/

#include "include/jdh.h"


big gen_rand(int size) 
{
  csprng    rng;
  long      seed_tod;
  char      seed_raw[256];
  int       i;
  big       b_rand=mirvar(0);

  for(i=0; i<sizeof(seed_raw); i++) 
      seed_raw[i]=arc4random() % ((unsigned)32767 + 1);
  
  time(&seed_tod);
  strong_init(&rng, strlen(seed_raw), seed_raw, seed_tod);
  strong_bigdig(&rng, size, 16, b_rand);
  
 return(b_rand);
}


big gen_n(int size)
{
  big       n=mirvar(0);
  big       n2=mirvar(0);
  big       two=mirvar(0);
  int       nprime=0;

  cinstr(two, "2");
  n=gen_rand(size);
 
   while(!isprime(n)) {
     incr(n, 1, n);
   }

   /* 
      generate a safe (germain) prime for n by ensuring 2*n + 1 is prime 
   */

   while(nprime==0) {

     multiply(n, two, n2);
     incr(n2, 1, n2);

     if(isprime(n2)) {   
       nprime=1;

     }
     else {
           incr(n, 1, n);
          }
   } 

 return(n);
}


big gen_nx(big x, big n)
{
  big       nx=mirvar(0);
 
  /* nx = g^x mod n */ 
  powltr(3, x, n, nx);
   
 return(nx);
}


big gen_key(big ny, big x, big n)
{
  big       key=mirvar(0);

  /* key = ny^x mod n */
  powmod(ny, x, n, key);

 return(key);
}


big hash_key(big key)
{
  char      seskey[DIGEST];
  char      buf[MAXBUF];
  big       digkey=mirvar(0);
  sha256    sh;
  int       i;

  big_to_bytes(0, key, buf, 0);

  shs256_init(&sh);

   for(i=0; i<strlen(buf); i++) 
       shs256_process(&sh, buf[i]); 
   
  shs256_hash(&sh, seskey);
  bytes_to_big(DIGEST, seskey, digkey);

 return(digkey);
}


aes aes_set_key(big digkey, char *iv)
{
  aes       a;
  char      akey[DIGEST];
  int       i;

  for(i=0; i<sizeof(iv); i++)
      iv[i]=arc4random() % ((unsigned)32767 + 1);
    
  big_to_bytes(0, digkey, akey, 0);
 

  if(!aes_init(&a, AESMODE, DIGEST, akey, iv)) {
  
     fprintf(stderr, ERR_AES_INIT);
     return;
  
  }

 return(a);
}


void aes_enc(aes a, char *buf, char *iv)
{
  int       i;

  /* MODE = PCFB/cipher feedback with error propagation */
  aes_reset(&a, AESMODE, iv);

  for(i=0; i<strlen(buf); i++) { 

      aes_encrypt(&a, &buf[i]);
             
  }  
}


void aes_dec(aes a, char *buf, char *iv)
{
  int       i;

  aes_reset(&a, AESMODE, iv);
    
  for(i=0; i<strlen(buf); i++) {

      aes_decrypt(&a, &buf[i]);

  }
}


/* Begin Test Driver */  
int main()
{
   miracl    *mip=mirsys(120, MAXBASE); 

   mip->IOBASE=16;  
   
   big       n=gen_n(NSIZE);              /* generate random safe prime (public) */

   big       xalice=gen_rand(XSIZE);      /* generate private integer for 1st party */
  
   big       xbob=gen_rand(XSIZE);        /* generate private integer for 2nd party */

   big       nx_alice=gen_nx(xalice, n);  /* calculate g(3)^xalice % n to send to bob */

   big       nx_bob=gen_nx(xbob, n);      /* calculate g(3)^xbob % n to send to alice */

   big       alicekey=gen_key(nx_bob, xalice, n); /* alice calculates nx_bob ^ xalice % n */

   big       bobkey=gen_key(nx_alice, xbob, n);  /* bob calculates nx_alice % xbob % n */                            

    
   /* Test if the 2 keys are identical */
   if(mr_compare(alicekey, bobkey) == 0) {

      printf("\nWe have matching keys\n\nAlice: ");
      cotnum(alicekey, stdout);
      printf("\nBob:   ");
      cotnum(bobkey, stdout);

   } else 
   {

      fprintf(stderr, "\nAn error occurred during key generation");
   
   }
  
   
   /* Use keys to initialize an AES struct for encryption */
                                                    
   big       digestkey_alice=hash_key(alicekey);  /* create an SHA256 bit hash using alice's key */
 
   big       digestkey_bob=hash_key(bobkey);      /* create an SHA256 bit hash using bob's key */
   

   char      iv_alice[16];                        /* used to generate random initialization vector */

   char      iv_bob[16];
  
   char      test_vector[]="abcdefghijklmnopqrstuvwxyz1234567890";  /* test vector */

   char      check_vector[]="abcdefghijklmnopqrstuvwxyz1234567890"; /* check vector */ 

   aes       aesctx_alice=aes_set_key(digestkey_alice, iv_alice); /* generate an aes struct for alice */
  
   aes       aesctx_bob=aes_set_key(digestkey_bob, iv_bob);       /* generate an aes struct for bob */

   
   aes_enc(aesctx_alice, test_vector, iv_alice); /* encrypt test vector (alice) */
   aes_dec(aesctx_alice, test_vector, iv_alice); /* decrypt test vector (alice) */

   if(strcmp(test_vector, check_vector)==0) {
 
      printf("\nEncryption/Decryption test passed for alice");
  
   } else
   {
  
      fprintf(stderr, "\nEncryption/Decryption test failed for alice");

   }

   aes_enc(aesctx_bob, test_vector, iv_bob); /* encrypt test vector (bob) */
   aes_dec(aesctx_bob, test_vector, iv_bob); /* decrypt test vector (bob) */

   if(strcmp(test_vector, check_vector)==0) {

      printf("\nEncryption/Decryption test passed for bob");
      printf("\nString1: %s\nString2: %s", test_vector, check_vector);  

   } else
   {

      fprintf(stderr, "\nEncryption/Decryption test failed for bob");
      printf("\nString1: %s\nString2: %s", test_vector, check_vector);

   }
   printf("\n");

   aes_end(&aesctx_alice);
   aes_end(&aesctx_bob);
  
   mirkill(n);
   mirkill(xalice);
   mirkill(xbob);
   mirkill(nx_alice);
   mirkill(nx_bob);
   mirkill(alicekey);
   mirkill(bobkey);
   mirkill(digestkey_alice);
   mirkill(digestkey_bob);
 
  return(0);   
}
