/**
 * A helper library for JavaCrypt which contains implementations of 
 * CubeHash, RC4, and TEA.
 *
 * @author Stephen Solis
 * @version 03/22/2012
 */
public class CryptoLib {

	/**
	 * CubeHash is one of the most simple yet cryptographically strong hash
	 * functions that exist. The algorithm was designed by Daniel J. Bernstein 
	 * (under funding by NIST) and is in the public domain.
	 * <br>
	 * This is an implementation of CubeHash 16/32-512, which was a 2nd-round 
	 * SHA-3–512-normal candidate.
	 * (16 = # of rounds, 32 = block size (in bytes), 512 = output size (in bits))
	 * <br>
	 * See http://cubehash.cr.yp.to for more details.
	 */
	public static class CubeHash {
		private static int[] state = new int[32]; //initialize the state (with zeros)

		/**
		 * Computes the CubeHash digest of a given message.
		 * @param message	the message to hash as a byte[]
		 * @return	the 512-bit digest of the given message as a byte[]
		 */
		public static byte[] doCubeHash (byte[] message) {
			/* STAGE 1 - initialization phase */
			state[0] = 64; //put initial values into state[] as described in the algorithm
			state[1] = 32;
			state[2] = 16;
			rounds(16); //do 16 initialization rounds
			//convert the input to integers (makes logical operations easier), then pad it 
			//as described in the algorithm
			//first, compute size of input[]
			int inputSize = message.length;
			inputSize++; //for the 1-byte padding specified in the algorithm
			inputSize += (32 - (inputSize % 32)); //add padding so inputSize is a multiple of 32
			//then, create input[] and fill it with message[] and padding
			byte[] inputBytes = new byte[inputSize];
			System.arraycopy(message, 0, inputBytes, 0, message.length); //copy message[] in
			inputBytes[message.length] = (byte)128; //has value 1000 0000 (binary)
			//convert inputBytes (a byte[]) to input (an int[])
			int[] input = new int[inputSize/4]; //an int has length 4 bytes
			for(int i = 0; i < inputSize; i += 4) {
				input[i/4] = ((inputBytes[i]&0xFF)) | 
							 ((inputBytes[i+1]&0xFF) << 8) | 
							 ((inputBytes[i+2]&0xFF) << 16) | 
							 ((inputBytes[i+3]&0xFF) << 24);
			}
		
			/* STAGE 2 - input processing phase */
			for (int block = 0; block < input.length; block += 8) {
				for (int i = 0; i < 8; i++) {
					//xor nth byte from input block with nth byte of state
					state[i] ^= input[block + i];
				}
				rounds(16); //do 16 rounds per message block
			}
		
			/* STAGE 3 - finalization phase */
			state[31] ^= 1; //xor 1 into last state word
			rounds(32); //32 finalization rounds
			//return first 512 bytes from state[]
			byte[] output = new byte[64]; //output is 512 bits = 64 bytes
			for (int i = 0; i < 16; i++){
				output[i*4] = (byte)(state[i]);
				output[(i*4)+1] = (byte)(state[i] >>> 8);
				output[(i*4)+2] = (byte)(state[i] >>> 16);
				output[(i*4)+3] = (byte)(state[i] >>> 24);
			}
			return output;
		}
		
		/**
		 * Performs n full CubeHash rounds on state[].
		 * @param n	the number of rounds to perform
		 */
		private static void rounds(int n) {
			//the step numbers referenced are from http://cubehash.cr.yp.to
			for (int i = 0; i < n; i++) {
				add_rotate(7, 25); //steps 1-2
				swap_xor_swap(8, 2); //3-5
				add_rotate(11, 21); //6-7
				swap_xor_swap(4, 1); //8-10
			}
		}
		
		/**
		 * Performs an 'add, rotate' step on state[].
		 */
		private static void add_rotate (int r, int s) {
			for (int i = 0; i < 16; i++) {
				state[16 + i] += state[i]; //add..
				state[i] = (state[i] << r) ^ (state[i] >>> s); //..then rotate
			}
		}
		
		/**
		 * Performs a 'swap, xor, swap' step on state[].
		 */
		private static void swap_xor_swap (int mask1, int mask2) {
			//the step numbers referenced are from http://cubehash.cr.yp.to
			
			int tmp, j; //temp variables
			for (int i = 0; i < 16; i++) {
				if ((i & mask1) != 0) { //does the [00klm] (step 3) or [0j0lm] (step 8) masks
					//swap + xor at the same time..
					j = i ^ mask1;
					tmp = state[i] ^ state[j + 16]; 
					state[i] = state[j] ^ state[i + 16];
					state[j] = tmp;
				}
			}
			for (int i = 16; i < 32; i++) {
				if ((i & mask2) != 0) { //does the [1jk0m] (step 5) or [1jkl0] (step 10) masks
					//..then swap
					j = i ^ mask2;
					tmp = state[i];
					state[i] = state[j];
					state[j] = tmp;
				}
			}
		}
	}
	
	/**
	 * RC4 is a very popular, very simple, very fast stream cypher designed 
	 * by Ron Rivest at RSA in 1987. It is not copyrighted, but was a trade 
	 * secret until 1994, when it was leaked.
	 * <br>
	 * See http://en.wikipedia.org/wiki/RC4 for more details.
	 */
	public static class RC4 {
	
		/**
		 * Performs RC4 encryption/decryption (RC4 is symmetric!) on the given
		 * data with the given key.
		 * @param key	the key to use
		 * @param data	the data to process
		 * @return	the processed data - will be the same size as the input
		 */
		public static byte[] doRC4(byte[] key, byte[] data) {
			int[] K = new int[256]; //holds the RC4 key array
			byte[] output = new byte[data.length]; //holds the output
			
			//convert key[] to an int[] mod 256, and store in keyInt[]
			int[] keyInt = new int[key.length];
			for (int i = 0; i < key.length; i++){
				//I have absolutely no idea why Java doesn't have an unsigned
				//int, so I have to do the conversion manually...
				if ((int)key[i] >= 0)
					keyInt[i] = (int)key[i]; 
				else
					keyInt[i] = (int)key[i] + 256;
			}
			
			//initialize the key array K
			for (int i = 0; i < 256; i++) {
				K[i] = i; //write numbers 0 to 256 into K
			}
			int a = 0; //from the spec
			int temp; //just a temp variable
			for (int i = 0; i < 256; i++) {
				a = (a + K[i] + keyInt[i % keyInt.length]) % 256;
				//swap K[i] with K[a]
				temp = K[i]; 
				K[i] = K[a];
				K[a] = temp;
			}
	
			/* once the key array has been generated, use the pseudo-random 
			   byte generator specified in the spec and xor those values with 
			   the input bytestream */
			int b = 0, c = 0; //from the spec
	
			for (int k = 0; k < data.length; k++) { //iterate through each input byte
				b = (b + 1) % 256;
				c = (c + K[b]) % 256;
				//swap K[b] with K[c]
				temp = K[b]; 
				K[b] = K[c];
				K[c] = temp;
				//xor K[(K[b] + K[c]) mod 256] with the current input byte 
				//and store it in output[k]
				//note: Java only does bitwise operations with ints, so we have
				//to cast to int and back to a byte at the end
				output[k] = (byte)((int)data[k] ^ (int)K[(K[b] + K[c]) % 256]);
			}
	
			return output;
		}
	}
	
	/**
	 * TEA (Tiny Encryption Algorithm) was designed by David Wheeler and 
	 * Roger Needham of the Cambridge Computer Laboratory in 1994, and was 
	 * designed to be the simplest (to implement) encryption algorithm ever.
	 * It has an unbalanced Feistel structure of 64 rounds. The algorithm and
	 * some reference implementations are in the public domain.
	 * <br>
	 * This is an implementation of XTEA (an improved version of the original
	 * TEA, designed in 1997).
	 * See http://en.wikipedia.org/wiki/XTEA for more details.
	 */
	public static class TEA {
		private static final int DELTA = 0x9E3779B9; //from the spec
	
		private static int[] subKeys = new int[4]; //see XTEA_init()
		private static int v0, v1; //from the spec
	
		/**
		 * Performs TEA encryption on the given data with the given key.
		 * @param key	the key to use - must be 16 bytes/128 bits long
		 * @param data	the data to encrypt - must be 8 bytes/64 bits long
		 * @return	the data, TEA encrypted - will be 8 bytes/64 bits long
		 */
		public static byte[] doTEA(byte[] key, byte[] data){
			XTEA_init(key, data);
			XTEA_encrypt();
			return XTEA_finalize();
		}
		
		/**
		 * Performs TEA decryption on the given data with the given key.
		 * @param key	the key to use - must be 16 bytes/128 bits long
		 * @param data	the data to process - must be 8 bytes/64 bits long
		 * @return	the decrypted data - will be 8 bytes/64 bits long
		 */
		public static byte[] doUnTEA(byte[] key, byte[] data){
			XTEA_init(key, data);
			XTEA_decrypt();
			return XTEA_finalize();
		}
		
		/**
		 * Initializes subKeys[], v0, and v1 with data from the given key[]
		 * and data[].
		 */
		private static void XTEA_init(byte[] key, byte[] data){
			//first, convert the byte[] key to 4 integers in subKeys:
			//this makes doing logical operations much easier
			for(int i = 0; i < 16; i += 4) {
				subKeys[i/4] = ((key[i]&0xFF)) | 
								((key[i+1]&0xFF) << 8) | 
								((key[i+2]&0xFF) << 16) | 
								((key[i+3]&0xFF) << 24);
			}
		
			//then, convert the byte[] data to two integers, v0 and v1 (as in the spec)
			v0 = ((data[0] & 0xFF)) | 
				 ((data[1] & 0xFF) <<  8) | 
				 ((data[2] & 0xFF) << 16) | 
				 ((data[3]) << 24);
			
			v1 = ((data[4] & 0xFF)) | 
				 ((data[5] & 0xFF) <<  8) | 
				 ((data[6] & 0xFF) << 16) | 
				 ((data[7]) << 24);
		}
		
		/**
		 * Performs XTEA encryption on v0 and v1 using subKeys[].
		 * This is straight from the spec.
		 */
		private static void XTEA_encrypt(){
			int sum = 0;
			//do 32 iterations (each iteration has 2 steps, so 64 rounds total)
			for (int i = 0; i < 32; i++) {
				v0 += ((v1 << 4 ^ v1 >>> 5) + v1) ^ (sum + subKeys[sum & 3]);
				sum += DELTA;
				v1 += ((v0 << 4 ^ v0 >>> 5) + v0) ^ (sum + subKeys[sum >> 11 & 3]);
			}
		}
		
		/**
		 * Performs XTEA decryption on v0 and v1 using subKeys[].
		 * This is straight from the spec.
		 */
		private static void XTEA_decrypt(){
			int sum = DELTA * 32;
			//do 32 iterations (each iteration has 2 steps, so 64 rounds total)
			for (int i = 0; i < 32; i++) {
				v1	-= ((v0 << 4 ^ v0 >>> 5) + v0) ^ (sum + subKeys[sum >> 11 & 3]);
				sum -= DELTA;
				v0 -= ((v1 << 4 ^ v1 >>> 5) + v1) ^ (sum + subKeys[sum & 3]);
			}
		}
	
		/**
		 * Converts v0 and v1 back to a byte[].
		 * @return	a byte[] representing v0 and v1
		 */
		private static byte[] XTEA_finalize(){
			byte[] out = new byte[8];
			
			//v0 first..
			out[0] = (byte)(v0);
			out[1] = (byte)(v0 >>> 8);
			out[2] = (byte)(v0 >>> 16);
			out[3] = (byte)(v0 >>> 24);
			//..then v1
			out[4] = (byte)(v1);
			out[5] = (byte)(v1 >>> 8);
			out[6] = (byte)(v1 >>> 16);
			out[7] = (byte)(v1 >>> 24);
			
			return out;
		}
	}
}