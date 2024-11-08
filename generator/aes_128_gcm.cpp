// Author: Yamya Reiki yamya.reiki14@gmail.com
// Based on: 
// 1. NIST Special Publication 800-38D Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC, Morris Dworkin
// 2. The Galois/Counter Mode of Operation (GCM) David A. McGrew, Cisco Systems, Inc., John Viega, Secure Software
// 3. aes-128-full.txt from https://github.com/n-for-1-auth/circuits/blob/main/aes/aes128_full.txt
#include <cstring>
#include <math.h>
#include "emp-tool/emp-tool.h"
using namespace emp;
typedef unsigned long long word64;

void print_many_bytes(block *output, int num_bytes) {
    // this function is taken from https://github.com/n-for-1-auth/circuits
	unsigned char digest_char[num_bytes];
	memset(digest_char, 0, num_bytes);

	bool output_bool[num_bytes * 8];
	ProtocolExecution::prot_exec->reveal(output_bool, PUBLIC, (block *) output, num_bytes * 8);

	for (int i = 0; i < num_bytes; i++) {
		int w = 1;
		for (int j = 0; j < 8; j++) {
			digest_char[i] += output_bool[i * 8 + j] * w;
			w <<= 1;
		}
	}

	for (int i = 0; i < num_bytes; i++) {
		printf("%02X ", digest_char[i]);
	}
	printf("\n");
}

// Right shift the bool array by 1 bit
void right_shift_bool_array(bool *array, int length) {
    for (int i = length - 1; i > 0; i--) {
        array[i] = array[i - 1];
    }
    array[0] = false;
}

// XOR two bool arrays
void xor_bool_arrays(bool *Z, bool *V) {
    for (int i = 0; i < 128; i++) {
        Z[i] ^= V[i];
    }
}

bool get_value(block a) {
	const static unsigned long long P0 = 2;
	const static unsigned long long S0 = 3;
    uint64_t *arr = (uint64_t*) &a;
    if (arr[0] == S0 or arr[0] == P0)
        return false;
    else return true;
}

void convert_block_array_to_bool_array(block *inputBlock, bool *bigEndianArray){
    bool bitArray[128]; // Array to store the bits in little-endian format
    // Populate the bitArray with the bits from block R
    for (int i = 0; i < 128; i++) {
        // Read bits in reverse order for little-endian format
        bool r = get_value(inputBlock[127-i]); // Get the bit from the corresponding position
        bitArray[i] = r; // Store the bit in the array
    }

    // Convert from little-endian to big-endian
    for (int byteIndex = 0; byteIndex < 16; byteIndex++) { // 16 bytes
        for (int bitIndex = 0; bitIndex < 8; bitIndex++) { // 8 bits per byte
            // Rearranging the bytes, but keeping the bits in each byte the same
            bigEndianArray[byteIndex * 8 + bitIndex] = 
                bitArray[(15 - byteIndex) * 8 + bitIndex]; 
        }
    }

}
void convert_bool_array_to_block_array(bool *a_bits, block *a, block one, block zero) {
    // Populate the `a` array in strict big-endian order
    for (int byteIndex = 0; byteIndex < 16; byteIndex++) {  // 16 bytes
        for (int bitIndex = 0; bitIndex < 8; bitIndex++) {   // 8 bits per byte
            // Calculate the position in the big-endian order
            int bitPosition = (byteIndex) * 8 + (7 - bitIndex);
            a[byteIndex * 8 + bitIndex] = a_bits[bitPosition] ? one : zero;
        }
    }
}

// Big Endian Galois Field multiplication for block datatype 
void gf_mul_be(block *a, block *b, block *result) {
    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);

    bool V[128];
    bool X[128];
    bool Z[128];
    
    for(int i = 0; i < 128; i++) {
        Z[i] = false;
    }

    convert_block_array_to_bool_array(b, V);
    convert_block_array_to_bool_array(a, X);
    
    // Perform the GF multiplication
    for (int i = 0; i < 128; i++) {
        if (X[i]) {
            xor_bool_arrays(Z, V);
        }

        bool lsbV = V[127];
        right_shift_bool_array(V, 128);

        if (lsbV) {
            V[0] ^= 1; // XOR with R's first bit (0xe1 in binary is 11100001)
            V[1] ^= 1;
            V[2] ^= 1;
            V[7] ^= 1;
        }
    }

    // Copy the result to the output
    convert_bool_array_to_block_array(Z, result, one, zero);
}

void ghash_h(block *hash_subkey, block *zero_block_plaintext, block *bit_string, int bit_string_len, block *output) {
   
    int n = ceil((float)bit_string_len/128); // Number of 128-bit blocks in the bit_string
    
    for (int j = 0; j < 128; j++) {
        output[j] = zero_block_plaintext[j];
    }

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < 128; j++) {
            output[j] = CircuitExecution::circ_exec->xor_gate(output[j], bit_string[j+ (i * 128)]); 
        }
        gf_mul_be(output, hash_subkey, output);
        // Perform Galois field multiplication of output by hash_subkey using emp inbuilt utility function (needs careful implementation: future work)
        /*for (int k = 0; k < 128; ++k) {
            gfmul(output[k], hash_subkey[k], &output[]);
        }*/
    }
}

void ciph(block *key, int key_len, block *plaintext,  int plaintext_len, block *ciphertext, int ciphertext_len_bytes){
    // the first 128 bits -> the key (in reverse order)
    // the rest of the 128 bits -> the plaintext (in reverse order)
    block input1[128];
    block input2[128];
    for(int i = 0; i < key_len; i++) {
        input1[i] = key[i];
    }
    for(int i = 0; i < plaintext_len; i++) {
        input2[i] = plaintext[i];
    }

    block ciphertext_raw[128];

    BristolFormat bf("./aes128_full.txt");
    bf.compute(ciphertext_raw, input1, input2);

    for(int i = 0; i < ciphertext_len_bytes; i++) {
        for(int j = 0; j < 8; j++) {
            ciphertext[i * 8 + j] = ciphertext_raw[i * 8 + (7 - j)];
        }
    }
}

void createJBlocks(block J[][128], int start, int end, int iv_len, block *iv, block one, block zero) {
    // Loop over each J block to generate
    for (int j = start; j < end; j++) {
        // Set the first 32 bits of each J block based on the binary representation of `j`
        for (int bit = 0; bit < 32; bit++) {
            J[j][bit] = ((j >> bit) & 1) ? one : zero;
        }
        
        // Fill remaining positions in J with IV data or zeros
        for (int i = 32; i < 128; i++) {
            J[j][i] = (i - 32 < iv_len) ? iv[i - 32] : zero;
        }
    }
}

void gctr_k(block *key, block *iv, int iv_len, int J_start_index, block *plaintext, int plaintext_len, block *ciphertext) {
    block zero = CircuitExecution::circ_exec->public_label(false);
    block one = CircuitExecution::circ_exec->public_label(true);
    
    int num_blocks = ceil((float)plaintext_len / 128);  // Number of blocks based on plaintext length
    int n = num_blocks + J_start_index;  // Total number of J blocks including the start offset
    block J[n][128];
    
    // Create J blocks from J_start_index up to n
    createJBlocks(J, J_start_index, n, iv_len, iv, one, zero);
    
    block ECB[128];
    for (int i = J_start_index; i < n; i++) {
        // Encrypt the J block to generate the keystream
        ciph(key, 128, J[i], 128, ECB, 16);
        
        // XOR the keystream with the appropriate 128-bit plaintext block
        for (int j = 0; j < 128 && ((i - J_start_index) * 128 + j) < plaintext_len; ++j) {
            int idx = (i - J_start_index) * 128 + j;
            ciphertext[idx] = CircuitExecution::circ_exec->xor_gate(plaintext[idx], ECB[j]);
        }
    }
}

void gcm_ae_k(block *aad, int aad_len, block *iv, int iv_len, block *key, block *plaintext, int plaintext_len,
              block *ciphertext, int ciphertext_len_bytes, block *tag) 
{
    // compute the hash subkey 
    block zero_block_plaintext[128];
	block zero = CircuitExecution::circ_exec->public_label(false);
    block one = CircuitExecution::circ_exec->public_label(true);
	for(int i = 0; i < 128; i++) {
		zero_block_plaintext[i] = zero;
	}
    block hash_subkey[128];
    ciph(key, 128, zero_block_plaintext, 128, hash_subkey, 16);    
    // the initial counter block index
    int J0 = 1;
    // compute the initial counter block and call gctr_k() to get the ciphertext
    gctr_k(key, iv, iv_len, J0+1, plaintext, plaintext_len, ciphertext);
    // compute u and v values
    int u = 128 * (ceil(((float)(ciphertext_len_bytes*8))/128)) - (ciphertext_len_bytes*8);
    int v = 128 * (ceil(((float)aad_len)/128)) - aad_len; 
    // create the ghash input string   
    int ghash_input_len = aad_len + v + (ciphertext_len_bytes*8) + u + 128; 
    word64 len64bit[2];
	len64bit[0] = 0x2800000000000000L; //TLS 1.3 AAD length
    len64bit[1] = 0x0002000000000000L; //Ciphertext length
    block len_bits[128];
	for (int i = 0; i < 2; i++) {
		word64 tmp = len64bit[i];
		for (int j = 0; j < 64; j++) {
			len_bits[i * 64 + j] = (tmp & 1) != 0 ? one : zero;
			tmp >>= 1;
		}
	} 
    block ghash_input[ghash_input_len];
    for (int i = 0; i < aad_len; i++){
        ghash_input[i] = aad[i];
    }
    int offset = aad_len;
    for(int i = 0; i < v; i++){
        ghash_input[i + offset] = zero;
    }
    offset = offset + v;
    for (int i = 0; i < ciphertext_len_bytes*8; i++){
        ghash_input[i + offset] = ciphertext[i];
    }
    offset = offset + ciphertext_len_bytes*8;
    for (int i = 0; i < u; i++){
        ghash_input[i + offset] = zero;
    }
    offset = offset + u;
    for (int i = 0; i < 128; i++){
        ghash_input[i + offset] = len_bits[i];
    }
    // compute ghash
    block ghash_output[128];
    ghash_h(hash_subkey, zero_block_plaintext, ghash_input, ghash_input_len, ghash_output);
    // compute the tag
    gctr_k(key, iv, iv_len, J0, ghash_output, 128, tag);    
}

void createAES_128_GCM_circuit(){
    setup_plain_prot(true, "aes-128-gcm-512-bit-plaintext-40-bit-aad.txt");  
    // TEST VECTOR 1:
    unsigned char test_aad[] = {
        0x17, 0x03, 0x03, 0x00, 0x15
    };

    unsigned char test_iv[] = {
        0x01, 0x6d, 0xbb, 0x38, 
        0xda, 0xa7, 0x6d, 0xfe,
        0xf1, 0x24, 0x03, 0x64
    };

    unsigned char test_key[] = {
        0x01, 0x6d, 0xbb, 0x38, 0xda, 0xa7, 0x6d, 0xfe,
		0x7d, 0xa3, 0x84, 0xeb, 0xf1, 0x24, 0x03, 0x64
    };
   
    unsigned char test_plaintext[] = {
        // the plaintext can be of arbitrary length up to 64 bytes
        // this example plaintext can be used to understand smtp commands encryption    
        0x54, 0x6f, 0x3a, 0x20, 0x20, 0x20, 0x20, 0x20, //To: fill with white space
      //0x52, 0x43, 0x50, 0x54, 0x20, 0x54, 0x4f, 0x3a, //RCPT TO:
        0x3c, 0x62, 0x62, 0x62, 0x65, 0x6c, 0x63, 0x68, //<email address
        0x40, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2d, // cannot be
        0x6c, 0x65, 0x76, 0x65, 0x6c, 0x2e, 0x63, 0x6f, // longer than
        0x6d, 0x3e, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // 52 chars> this can accomodate 95% email addresses in world
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // fill  
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // with
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x0d, 0x0a  // white space\r\n
    };
/*  TEST VECTOR 2: 
    unsigned char test_aad[] = {
        0x16, 0x03, 0x01, 0x00, 0x10
    };

    unsigned char test_iv[] = {
        0x02, 0x7e, 0xcc, 0x49, 
        0xdb, 0xb8, 0x7e, 0xff,
        0xe2, 0x34, 0x12, 0x75
    };

    unsigned char test_key[] = {
        0x02, 0x7e, 0xcc, 0x49, 0xdb, 0xb8, 0x7e, 0xff,
        0x8d, 0xb4, 0x95, 0xfc, 0xe2, 0x34, 0x12, 0x75
    };

    unsigned char test_plaintext[] = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x74, //Hello, t
        0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, //his is a
        0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x65, 0x6d, // test em
        0x61, 0x69, 0x6c, 0x20, 0x61, 0x64, 0x64, 0x72, //ail addr
        0x65, 0x73, 0x73, 0x2e, 0x20, 0x20, 0x20, 0x20, //ess.  
        0x3c, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, //<exampl
        0x40, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2e, //@domain
        0x63, 0x6f, 0x6d, 0x3e, 0x0d, 0x0a, 0x20, 0x20  // .com>\r\n
    };
    
    Expected CIPHERTEXT: 
    EF 1B F2 FC DA 5D 96 C4 6C 0D F5 C6 2A 4B 4D 9E 
    15 BA B3 F6 B3 B8 58 81 B4 F4 3C F0 85 32 14 10 
    F1 4E 3E A2 63 E4 19 F6 7F F6 D6 77 A4 C0 D3 BE 
    98 0C 3F F8 03 B0 C2 CA 6E DE D0 D3 C3 25 7C C4
    Expected TAG: 
    AB B7 C3 1E 4D BA B3 22 2D F3 B0 1E A7 E1 7C A7 
*/    
    bool test_aad_input[5 * 8];
    for (int i = 0; i < 5; i++) {
        int w = test_aad[i];
        for (int j = 0; j < 8; j++) {
            test_aad_input[i * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_iv_input[12 * 8];
    for (int i = 0; i < 12; i++) {
        int w = test_iv[i];
        for (int j = 0; j < 8; j++) {
            test_iv_input[(11-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_key_input[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key[i];
        for (int j = 0; j < 8; j++) {
            test_key_input[(15-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_plaintext_input[64 * 8];
    for (int i = 0; i < 64; i++) {
        int w = test_plaintext[i];
        for (int j = 0; j < 8; j++) {
            test_plaintext_input[i * 8 + j] = w & 1;
            w >>= 1;
        }
    }
    
    // create inputs for circuit
    block aad[5*8];
    block iv[12*8];
    block key[16*8];
    block plaintext[64*8];
    ProtocolExecution::prot_exec->feed(aad, ALICE, test_aad_input, 5 * 8);
    ProtocolExecution::prot_exec->feed(iv, ALICE, test_iv_input, 12 * 8);
    ProtocolExecution::prot_exec->feed(key, ALICE, test_key_input, 16 * 8);
    ProtocolExecution::prot_exec->feed(plaintext, ALICE, test_plaintext_input, 64 * 8);

    block ciphertext[64*8];
    // Expected CIPHERTEXT: 
    // E2 BA 30 7C 52 9B 3A 2C DF E9 1F 27 10 FA 6D A5 
    // 25 68 DF 8A 4F FD 74 C2 6B DC 66 80 5C 79 3C B0 
    // 21 C2 F3 C2 3D FB F5 E2 4C F6 D9 83 64 E7 B7 00 
    // 45 F7 57 A6 AB B3 59 E4 5E A9 E5 68 E0 70 1B A5
    block tag[16*8];
    // Expected TAG:
    // D2 79 FD CA 8C CA 46 02 8D 28 98 CD 03 D4 30 9F
    gcm_ae_k(aad, 5*8, iv, 12*8, key, plaintext, 64*8, ciphertext, 64, tag);
    // create output for circuit
    
    print_many_bytes(ciphertext, 64);
    print_many_bytes(tag, 16);
    finalize_plain_prot();
}

int main(int argc, char **argv) {
    createAES_128_GCM_circuit();
	return 0;
}
