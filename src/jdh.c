/* 

  Diffie Hellman Key Exchange (Slow) Demo Implementation
  JB Gericke
  2006

*/

#include "../include/jdh.h"


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
  
  
   mirkill(n);
   mirkill(xalice);
   mirkill(xbob);
   mirkill(nx_alice);
   mirkill(nx_bob);
   mirkill(alicekey);
   mirkill(bobkey);
 
  return(0);   
}
