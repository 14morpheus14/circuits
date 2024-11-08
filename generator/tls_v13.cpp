#include <cstring>
#include <time.h>
#include <stdbool.h>
#include "emp-tool/emp-tool.h"
using namespace emp;

typedef unsigned int word32;

void sum_32byte_blocks(block *input1, block *input2, block *sum){
    block zero = CircuitExecution::circ_exec->public_label(false);
    for (int i = 0; i < 256; i++){
        sum[i] = zero;
    }
    block carry = zero;
    
    for (int i = 0; i < 256; i++ ){
        sum[i] = CircuitExecution::circ_exec->xor_gate(CircuitExecution::circ_exec->xor_gate(input1[i], input2[i]), carry);
        block next_carry = CircuitExecution::circ_exec->xor_gate(CircuitExecution::circ_exec->and_gate(input1[i], input2[i]), CircuitExecution::circ_exec->and_gate(CircuitExecution::circ_exec->xor_gate(input1[i], input2[i]), carry));  
        carry = next_carry;
    }
}

void convert_256bit_bool_array_to_block_array(bool *a_bits, block *a, block one, block zero) {
    // Populate the `a` array in strict big-endian order
    for (int byteIndex = 0; byteIndex < 32; byteIndex++) {  // 32 bytes
        for (int bitIndex = 0; bitIndex < 8; bitIndex++) {   // 8 bits per byte
            // Calculate the position in the big-endian order
            int bitPosition = (byteIndex) * 8 + (7 - bitIndex);
            a[byteIndex * 8 + bitIndex] = a_bits[bitPosition] ? one : zero;
        }
    }
}

void convert_128bit_bool_array_to_block_array(bool *a_bits, block *a, block one, block zero) {
    // Populate the `a` array in strict big-endian order
    for (int byteIndex = 0; byteIndex < 16; byteIndex++) {  // 16 bytes
        for (int bitIndex = 0; bitIndex < 8; bitIndex++) {   // 8 bits per byte
            // Calculate the position in the big-endian order
            int bitPosition = (byteIndex) * 8 + (7 - bitIndex);
            a[byteIndex * 8 + bitIndex] = a_bits[bitPosition] ? one : zero;
        }
    }
}

void convert_96bit_bool_array_to_block_array(bool *a_bits, block *a, block one, block zero) {
    // Populate the `a` array in strict big-endian order
    for (int byteIndex = 0; byteIndex < 12; byteIndex++) {  // 16 bytes
        for (int bitIndex = 0; bitIndex < 8; bitIndex++) {   // 8 bits per byte
            // Calculate the position in the big-endian order
            int bitPosition = (byteIndex) * 8 + (7 - bitIndex);
            a[byteIndex * 8 + bitIndex] = a_bits[bitPosition] ? one : zero;
        }
    }
}

void xor_512_bits(block *A, block *B, block *C) {
    for (int i = 0; i < 512; i++) {
        C[i] = CircuitExecution::circ_exec->xor_gate(A[i], B[i]);
    }
}

void xor_432_bits(block *A, block *B, block *C) {
    for (int i = 0; i < 432; i++) {
        C[i] = CircuitExecution::circ_exec->xor_gate(A[i], B[i]);
    }
}

void xor_256_bits(block *A, block *B, block *C) {
    for (int i = 0; i < 256; i++) {
        C[i] = CircuitExecution::circ_exec->xor_gate(A[i], B[i]);
    }
}

void xor_128_bits(block *A, block *B, block *C) {
    for (int i = 0; i < 128; i++) {
        C[i] = CircuitExecution::circ_exec->xor_gate(A[i], B[i]);
    }
}

void xor_96_bits(block *A, block *B, block *C) {
    for (int i = 0; i < 96; i++) {
        C[i] = CircuitExecution::circ_exec->xor_gate(A[i], B[i]);
    }
}

void create_256bit_shares(block *input, block *share1, block *share2){

    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);
        // Seed random number generator
    srand((unsigned int)time(NULL));

    // Step 1: Generate 32 random bytes (256 bits)
    unsigned char randomBytes[256/8];
    for (int i = 0; i < 256/8; i++) {
        randomBytes[i] = (unsigned char)(rand() % 256);  // Generate a random byte
    }

    // Step 2: Create a bool array and populate it with bit values
    bool bitArray[256];
    for (int i = 0; i < 256/8; i++) {
        for (int j = 0; j < 8; j++) {
            // Extract each bit from the byte and store it in the bool array
            bitArray[i * 8 + j] = (randomBytes[i] >> (7 - j)) & 1;
        }
    }

    convert_256bit_bool_array_to_block_array(bitArray, share1, one, zero);

    //PRG prg; //can be used instead
    //prg.random_block(share1, 256);
    xor_256_bits(share1, input, share2);
}

void create_128bit_shares(block *input, block *share1, block *share2){

    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);

    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Step 1: Generate 16 random bytes (128 bits)
    unsigned char randomBytes[128 / 8];
    for (int i = 0; i < 128 / 8; i++) {
        randomBytes[i] = (unsigned char)(rand() % 256);  // Generate a random byte
    }

    // Step 2: Create a bool array and populate it with bit values
    bool bitArray[128];
    for (int i = 0; i < 128 / 8; i++) {
        for (int j = 0; j < 8; j++) {
            // Extract each bit from the byte and store it in the bool array
            bitArray[i * 8 + j] = (randomBytes[i] >> (7 - j)) & 1;
        }
    }

    // Convert the 128-bit bool array to a block array
    convert_128bit_bool_array_to_block_array(bitArray, share1, one, zero);

    //block dynamic_seed = emp::makeBlock(time(nullptr), time(nullptr) ^ 0x55555555);
    //PRG prg(&dynamic_seed); // can be used instead
    //prg.random_block(share1, 128);
    // XOR the share1 with input to get share2
    xor_128_bits(share1, input, share2);
}

void create_96bit_shares(block *input, block *share1, block *share2){

    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);
        // Seed random number generator
    srand((unsigned int)time(NULL));

    // Step 1: Generate 32 random bytes (256 bits)
    unsigned char randomBytes[96/8];
    for (int i = 0; i < 96/8; i++) {
        randomBytes[i] = (unsigned char)(rand() % 256);  // Generate a random byte
    }

    // Step 2: Create a bool array and populate it with bit values
    bool bitArray[96];
    for (int i = 0; i < 96/8; i++) {
        for (int j = 0; j < 8; j++) {
            // Extract each bit from the byte and store it in the bool array
            bitArray[i * 8 + j] = (randomBytes[i] >> (7 - j)) & 1;
        }
    }

    convert_96bit_bool_array_to_block_array(bitArray, share1, one, zero);

    //PRG prg; //can be used instead
    //prg.random_block(share1, 256);
    xor_96_bits(share1, input, share2);
}

void change_endian(block *input, block *output, int input_len) {
	if (input_len % 8 != 0) {
		error("The circuit synthesizer can only convert the endianness for bytes.");
	}

	int num_bytes = input_len / 8;
	for (int i = 0; i < num_bytes; i++) {
		for (int j = 0; j < 8; j++) {
			output[i * 8 + j] = input[i * 8 + (7 - j)];
		}
	}
}

void print_hash(block *output) {
	unsigned char digest_char[32];
	memset(digest_char, 0, 32);

	bool output_bool[256];
	ProtocolExecution::prot_exec->reveal(output_bool, PUBLIC, (block *) output, 256);

	for (int i = 0; i < 8; i++) {
		for (int j = 0; j < 4; j++) {
			int w = 1;
			for (int k = 0; k < 8; k++) {
				digest_char[i * 4 + j] += output_bool[i * 32 + 8 * j + k] * w;
				w <<= 1;
			}
		}
	}

	for (int i = 0; i < 32; i++) {
		printf("%02X ", digest_char[i]);
	}
	printf("\n");
}

void print_many_bytes(block *output, int num_bytes) {
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

int get_padded_len(int L) {
	// find K such that L + 1 + K + 64 is a multiple of 512
	int K = 512 - ((L + 1 + 64) % 512);
	K %= 512;    // If L + 1 + 64 is already a multiple of 512, K = 0

	return L + 1 + K + 64;
}

void padding(block *input, block *output, int input_len) {
	block one = CircuitExecution::circ_exec->public_label(true);
	block zero = CircuitExecution::circ_exec->public_label(false);

	for (int i = 0; i < input_len; i++) {
		output[i] = input[i];
	}

	int offset = input_len;

	// add one bit "1"
	output[offset++] = one;

	// find K such that L + 1 + K + 64 is a multiple of 512
	int K = 512 - ((input_len + 1 + 64) % 512);
	K %= 512;    // If L + 1 + 64 is already a multiple of 512, K = 0

	// add K bits "0"
	for (int i = 0; i < K; i++) {
		output[offset++] = zero;
	}

	if (input_len > 8191) {
		error("The circuit synthesizer assumes that input_len is small (< 8192 bits).");
	}

	// add the length of L
	// for simplicity, assume that the higher 48 bits are zero---since our input is going to be small anyway
	// the remaining 16 bits give you 2^15-1 bits to spend, about 8KB
	for (int i = 0; i < 48; i++) {
		output[offset++] = zero;
	}

	for (int i = 0; i < 16; i++) {
		int bool_test = (input_len & (1 << (16 - 1 - i))) != 0;
		output[offset++] = bool_test ? one : zero;
	}
}

void sha256(block *input, block *output, int input_len) {
	// new input
	auto input_new = new block[input_len];

	// reverse the bits
	change_endian(input, input_new, input_len);

	// first, do the padding
	int padded_len = get_padded_len(input_len);

	// allocate the padding
	block *padded_input = new block[padded_len];

	// pad
	padding(input_new, padded_input, input_len);

	delete[] input_new;

	// number of blocks
	int num_blocks = padded_len / 512;

	// start the hashing
	// first block
	word32 digest[8];
	digest[0] = 0x6A09E667L;
	digest[1] = 0xBB67AE85L;
	digest[2] = 0x3C6EF372L;
	digest[3] = 0xA54FF53AL;
	digest[4] = 0x510E527FL;
	digest[5] = 0x9B05688CL;
	digest[6] = 0x1F83D9ABL;
	digest[7] = 0x5BE0CD19L;

	block one = CircuitExecution::circ_exec->public_label(true);
	block zero = CircuitExecution::circ_exec->public_label(false);

	auto input_to_sha256_circuit = new block[768];
	block output_from_sha256_circuit[256];

	block digest_bits[256];
	for (int i = 0; i < 8; i++) {
		word32 tmp = digest[i];
		for (int j = 0; j < 32; j++) {
			digest_bits[i * 32 + j] = (tmp & 1) != 0 ? one : zero;
			tmp >>= 1;
		}
	}

	for (int b = 0; b < num_blocks; b++) {
		// the first 512 bits -> the padded data
		// the rest of the 256 bits -> the 8 * 32 bits of the digest values

		for (int i = 0; i < 512; i++) {
			input_to_sha256_circuit[i] = padded_input[b * 512 + i];
		}

		for (int i = 0; i < 256; i++) {
			input_to_sha256_circuit[512 + i] = digest_bits[i];
		}

		BristolFormat bf("./sha-256-multiblock-aligned.txt");
		bf.compute(output_from_sha256_circuit, input_to_sha256_circuit, input_to_sha256_circuit);

		for (int i = 0; i < 256; i++) {
			digest_bits[i] = output_from_sha256_circuit[i];
		}
	}

	for (int i = 0; i < 8; i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 8; k++) {
				output[i * 32 + j * 8 + k] = output_from_sha256_circuit[i * 32 + 8 * (3 - j) + k];
			}
		}
	}

	delete[] padded_input;
	delete[] input_to_sha256_circuit;
}

void hmac(block *key, int key_len, block *data, int data_len, block *output) {
	// reject key that is too long
	if (key_len > 512) {
		error("The circuit synthesizer only supports key that is shorter or equal to 512 bits.");
	}

	// create the ipad
	unsigned char ipad_bytes[512 / 8];
	for (int i = 0; i < 64; i++) {
		ipad_bytes[i] = 0x36;
	}

	block one = CircuitExecution::circ_exec->public_label(true);
	block zero = CircuitExecution::circ_exec->public_label(false);

	// convert ipad into bits
	block ipad[512];
	for (int i = 0; i < 64; i++) {
		unsigned char tmp = ipad_bytes[i];
		for (int j = 0; j < 8; j++) {
			ipad[i * 8 + j] = (tmp & 1) != 0 ? one : zero;
			tmp >>= 1;
		}
	}

	// assemble the hash function input
	block input_to_hash_function[512 + data_len];
	for (int i = 0; i < 512; i++) {
		input_to_hash_function[i] = ipad[i];
	}
	for (int i = 0; i < key_len; i++) {
		input_to_hash_function[i] = CircuitExecution::circ_exec->xor_gate(input_to_hash_function[i], key[i]);
	}
	for (int i = 0; i < data_len; i++) {
		input_to_hash_function[512 + i] = data[i];
	}

	// allocate the hash function output
	block output_from_hash_function[256];

	// compute the inner hash
	sha256(input_to_hash_function, output_from_hash_function, 512 + data_len);

	// create the opad
	unsigned char opad_bytes[512 / 8];
	for (int i = 0; i < 64; i++) {
		opad_bytes[i] = 0x5c;
	}

	// convert opad into bits
	block opad[512];
	for (int i = 0; i < 64; i++) {
		unsigned char tmp = opad_bytes[i];
		for (int j = 0; j < 8; j++) {
			opad[i * 8 + j] = (tmp & 1) != 0 ? one : zero;
			tmp >>= 1;
		}
	}

	block input_2_to_hash_function[512 + 256];
	for (int i = 0; i < 512; i++) {
		input_2_to_hash_function[i] = opad[i];
	}
	for (int i = 0; i < key_len; i++) {
		input_2_to_hash_function[i] = CircuitExecution::circ_exec->xor_gate(input_2_to_hash_function[i], key[i]);
	}
	for (int i = 0; i < 256; i++) {
		input_2_to_hash_function[512 + i] = output_from_hash_function[i];
	}

	// allocate the hash function output
	block output_2_from_hash_function[256];

	// compute the outer hash
	sha256(input_2_to_hash_function, output_2_from_hash_function, 512 + 256);

	for (int i = 0; i < 256; i++) {
		output[i] = output_2_from_hash_function[i];
	}
}

void hkdf_extract(block *salt, int salt_len, block *ikm, int ikm_len, block *output) {
	if (salt_len == 0) {
		block key[256];

		block zero = CircuitExecution::circ_exec->public_label(false);
		for (int i = 0; i < 256; i++) {
			key[i] = zero;
		}

		hmac(key, 256, ikm, ikm_len, output);
	} else {
		hmac(salt, salt_len, ikm, ikm_len, output);
	}
}

void hkdf_expand(block *key, int key_len, block *info, int info_len, block *output, int output_byte_len) {
	if (key_len < 256) {
		error("Key length for HKDF expand must be at least 256 bits.\n");
	}

	int N = (output_byte_len + 32 - 1) / 32;

	block cur_T[256];
	int cur_T_len = 0;
	auto input = new block[cur_T_len + info_len + 8];
	for (int i = 1; i <= N; i++) {
        //auto input = new block[cur_T_len + info_len + 8]; // This line is moved before loop to fix memory leak
		for (int j = 0; j < cur_T_len; j++) {
			input[j] = cur_T[j];
		}
		for (int j = 0; j < info_len; j++) {
			input[cur_T_len + j] = info[j];
		}

		bool ctr[8];
		int w = i;
		for (int j = 0; j < 8; j++) {
			ctr[j] = w & 1;
			w >>= 1;
		}

		block one = CircuitExecution::circ_exec->public_label(true);
		block zero = CircuitExecution::circ_exec->public_label(false);

		for (int j = 0; j < 8; j++) {
			input[cur_T_len + info_len + j] = ctr[j] == 1 ? one : zero;
		}

		hmac(key, key_len, input, cur_T_len + info_len + 8, cur_T);
		cur_T_len = 256;
		for (int j = 0; j < 256; j++) {
			if (((i - 1) * 256 + j) < output_byte_len * 8) {
				output[(i - 1) * 256 + j] = cur_T[j];
			}
		}
	}
    delete[] input; // Here we delete memory area to fix a leak
}

void hkdf_expand_label(block *key, int key_len, const char *label, block *context, int context_len, block *output,
					   int output_byte_len) {
	char long_label[255];
	sprintf(long_label, "tls13 %s", label);

	int long_label_len = strlen(long_label);

	block hkdf_label[16 + 8 + long_label_len * 8 + 8 + context_len];

	block one = CircuitExecution::circ_exec->public_label(true);
	block zero = CircuitExecution::circ_exec->public_label(false);

	int offset = 0;
	int w;

	w = output_byte_len;
	for (int i = 0; i < 8; i++) {
		hkdf_label[8 + i] = w & 1 ? one : zero;
		w >>= 1;
	}
	for (int i = 0; i < 8; i++) {
		hkdf_label[i] = w & 1 ? one : zero;
		w >>= 1;
	}

	offset += 16;

	w = long_label_len;
	for (int i = 0; i < 8; i++) {
		hkdf_label[offset++] = w & 1 ? one : zero;
		w >>= 1;
	}

	for (int i = 0; i < long_label_len; i++) {
		w = (unsigned char) long_label[i];
		for (int j = 0; j < 8; j++) {
			hkdf_label[offset++] = w & 1 ? one : zero;
			w >>= 1;
		}
	}

	w = context_len / 8;    // length in bytes
	for (int i = 0; i < 8; i++) {
		hkdf_label[offset++] = w & 1 ? one : zero;
		w >>= 1;
	}

	for (int i = 0; i < context_len; i++) {
		hkdf_label[offset++] = context[i];
	}

	hkdf_expand(key, key_len, hkdf_label, 16 + 8 + long_label_len * 8 + 8 + context_len, output, output_byte_len);
}

// Handshake
void DeriveHandshakeSecret_PreMasterSecret() {
	setup_plain_prot(true, "DeriveHandshakeSecret_PreMasterSecret.txt");
	unsigned char derived_secert[] =
			{
					0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5,
					0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
					0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c,
					0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba
			};

    unsigned char test_shared_secret_1[] = 
            {
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

    unsigned char test_shared_secret_2[] =
            {
                    0xcf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf,
                    0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad,
                    0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc,
                    0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24
            };
    
    unsigned char test_output_mask_1[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5,
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5
            };
    
    unsigned char test_output_mask_2[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcf, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa3,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xa0, 0xa4,
                    0xde, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xab, 0xa7
            };
    
	block one = CircuitExecution::circ_exec->public_label(true);
	block zero = CircuitExecution::circ_exec->public_label(false);

	block salt[256];
	for (int i = 0; i < 32; i++) {
		int w = derived_secert[i];
		for (int j = 0; j < 8; j++) {
			salt[i * 8 + j] = w & 1 ? one : zero;
			w >>= 1;
		}
	}
    
    bool shared_secret_share1[256];
    for (int i = 0; i < 32; i++) {
		int w = test_shared_secret_1[i];
		for (int j = 0; j < 8; j++) {
			shared_secret_share1[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

    bool shared_secret_share2[256];
    for (int i = 0; i < 32; i++) {
		int w = test_shared_secret_2[i];
		for (int j = 0; j < 8; j++) {
			shared_secret_share2[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

    bool outputmask1[256];
    for (int i = 0; i < 32; i++) {
		int w = test_output_mask_1[i];
		for (int j = 0; j < 8; j++) {
			outputmask1[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

    bool outputmask2[256];
    for (int i = 0; i < 32; i++) {
		int w = test_output_mask_2[i];
		for (int j = 0; j < 8; j++) {
			outputmask2[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

	block ss_share1[256];
	ProtocolExecution::prot_exec->feed(ss_share1, ALICE, shared_secret_share1, 256);
    block output_mask1[256];
    ProtocolExecution::prot_exec->feed(output_mask1, ALICE, outputmask1, 256);
    block ss_share2[256];
	ProtocolExecution::prot_exec->feed(ss_share2, BOB, shared_secret_share2, 256);
    block output_mask2[256];
    ProtocolExecution::prot_exec->feed(output_mask2, BOB, outputmask2, 256);
    block ikm[256];
    sum_32byte_blocks(ss_share1, ss_share2, ikm);
	block handshake_secret_premaster_secret[256];
    hkdf_extract(salt, 256, ikm, 256, handshake_secret_premaster_secret);
    block handshake_secret_premaster_secret_share1[256];
    block handshake_secret_premaster_secret_share2[256];
    create_256bit_shares(handshake_secret_premaster_secret, handshake_secret_premaster_secret_share1, handshake_secret_premaster_secret_share2);
	block output1[256];
    block output2[256];
    xor_256_bits(handshake_secret_premaster_secret_share1, output_mask1, output1);
    xor_256_bits(handshake_secret_premaster_secret_share2, output_mask2, output2);
    print_hash(output1);
    print_hash(output2);
	// expected handshake_secret: fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a
	finalize_plain_prot();
}

void DeriveClientHandshakeSecret() {
	setup_plain_prot(true, "DeriveClientHandshakeSecret.txt");

	unsigned char handshake_secret_test_data1[]=
			{
					0xf5, 0x35, 0x8c, 0x24, 0x36, 0x52, 0x8a, 0x22,
					0x2f, 0x80, 0x26, 0xee, 0x3d, 0xbe, 0x88, 0x7d,
					0x39, 0xc3, 0x1f, 0x6f, 0xd3, 0x51, 0x8e, 0x51,
					0x4b, 0xdb, 0xe0, 0xa9, 0xf0, 0x99, 0x3c, 0xe5
			};

	unsigned char hello_hash_test_data[] =
			{
					0xda, 0x75, 0xce, 0x11, 0x39, 0xac, 0x80, 0xda,
					0xe4, 0x04, 0x4d, 0xa9, 0x32, 0x35, 0x0c, 0xf6,
					0x5c, 0x97, 0xcc, 0xc9, 0xe3, 0x3f, 0x1e, 0x6f,
					0x7d, 0x2d, 0x4b, 0x18, 0xb7, 0x36, 0xff, 0xd5
			};
    
    unsigned char handshake_secret_test_data2[] =
            {
                    0x0E, 0xAA, 0x44, 0x22, 0xBF, 0xE1, 0x2F, 0xF2,
                    0x03, 0xB3, 0x02, 0xD5, 0xCB, 0x24, 0x93, 0x66, 
                    0x19, 0xB3, 0x4A, 0xE7, 0x74, 0xC5, 0xBE, 0x1B, 
                    0x25, 0xAA, 0xC0, 0xBC, 0xAE, 0x46, 0x28, 0x7F 
            };


	bool handshake_secret_plaintext1[32 * 8];
	for (int i = 0; i < 32; i++) {
		int w = handshake_secret_test_data1[i];
		for (int j = 0; j < 8; j++) {
			handshake_secret_plaintext1[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

	bool hello_hash_plaintext[256];
	for (int i = 0; i < 32; i++) {
		int w = hello_hash_test_data[i];
		for (int j = 0; j < 8; j++) {
			hello_hash_plaintext[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool handshake_secret_plaintext2[32 * 8];
	for (int i = 0; i < 32; i++) {
		int w = handshake_secret_test_data2[i];
		for (int j = 0; j < 8; j++) {
			handshake_secret_plaintext2[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

	block handshake_secret1[256];
	ProtocolExecution::prot_exec->feed(handshake_secret1, ALICE, handshake_secret_plaintext1, 256);

	block hello_hash[256];
	ProtocolExecution::prot_exec->feed(hello_hash, ALICE, hello_hash_plaintext, 256);

    block handshake_secret2[256];
	ProtocolExecution::prot_exec->feed(handshake_secret2, BOB, handshake_secret_plaintext2, 256);
    
    block handshake_secret[256];
    xor_256_bits(handshake_secret1, handshake_secret2, handshake_secret);
	// client_handshake_traffic_secret = HKDF-Expand-Label(
	//    key = handshake_secret,
	//    label = "c hs traffic",
	//    context = hello_hash,
	//    len = 32)
	
    block client_handshake_traffic_secret[256];
    // We are only parallelizing only the compilation, not really the circuit, unfortunately.
    //std::thread client_handshake_thread([&]() {
       hkdf_expand_label(handshake_secret, 256, "c hs traffic", hello_hash, 256, client_handshake_traffic_secret, 32);
    //});

    //client_handshake_thread.join();
    
    print_many_bytes(client_handshake_traffic_secret, 32);
	finalize_plain_prot();
}

void DeriveServerHandshakeSecret() {
	setup_plain_prot(true, "DeriveServerHandshakeSecret.txt");

	unsigned char handshake_secret_test_data1[]=
			{
					0xf5, 0x35, 0x8c, 0x24, 0x36, 0x52, 0x8a, 0x22,
					0x2f, 0x80, 0x26, 0xee, 0x3d, 0xbe, 0x88, 0x7d,
					0x39, 0xc3, 0x1f, 0x6f, 0xd3, 0x51, 0x8e, 0x51,
					0x4b, 0xdb, 0xe0, 0xa9, 0xf0, 0x99, 0x3c, 0xe5
			};

	unsigned char hello_hash_test_data[] =
			{
					0xda, 0x75, 0xce, 0x11, 0x39, 0xac, 0x80, 0xda,
					0xe4, 0x04, 0x4d, 0xa9, 0x32, 0x35, 0x0c, 0xf6,
					0x5c, 0x97, 0xcc, 0xc9, 0xe3, 0x3f, 0x1e, 0x6f,
					0x7d, 0x2d, 0x4b, 0x18, 0xb7, 0x36, 0xff, 0xd5
			};
    
    unsigned char handshake_secret_test_data2[] =
            {
                    0x0E, 0xAA, 0x44, 0x22, 0xBF, 0xE1, 0x2F, 0xF2,
                    0x03, 0xB3, 0x02, 0xD5, 0xCB, 0x24, 0x93, 0x66, 
                    0x19, 0xB3, 0x4A, 0xE7, 0x74, 0xC5, 0xBE, 0x1B, 
                    0x25, 0xAA, 0xC0, 0xBC, 0xAE, 0x46, 0x28, 0x7F 
            };


	bool handshake_secret_plaintext1[32 * 8];
	for (int i = 0; i < 32; i++) {
		int w = handshake_secret_test_data1[i];
		for (int j = 0; j < 8; j++) {
			handshake_secret_plaintext1[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

	bool hello_hash_plaintext[256];
	for (int i = 0; i < 32; i++) {
		int w = hello_hash_test_data[i];
		for (int j = 0; j < 8; j++) {
			hello_hash_plaintext[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool handshake_secret_plaintext2[32 * 8];
	for (int i = 0; i < 32; i++) {
		int w = handshake_secret_test_data2[i];
		for (int j = 0; j < 8; j++) {
			handshake_secret_plaintext2[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

	block handshake_secret1[256];
	ProtocolExecution::prot_exec->feed(handshake_secret1, ALICE, handshake_secret_plaintext1, 256);

	block hello_hash[256];
	ProtocolExecution::prot_exec->feed(hello_hash, ALICE, hello_hash_plaintext, 256);

    block handshake_secret2[256];
	ProtocolExecution::prot_exec->feed(handshake_secret2, BOB, handshake_secret_plaintext2, 256);
    
    block handshake_secret[256];
    xor_256_bits(handshake_secret1, handshake_secret2, handshake_secret);
	
    // server_handshake_traffic_secret = HKDF-Expand-Label(
	//    key = handshake_secret,
	//    label = "s hs traffic",
	//    context = hello_hash,
	//    len = 32)
	block server_handshake_traffic_secret[256];
    // We are only parallelizing only the compilation, not really the circuit, unfortunately.
    //std::thread server_handshake_thread([&]() {
       hkdf_expand_label(handshake_secret, 256, "s hs traffic", hello_hash, 256, server_handshake_traffic_secret, 32);
    //});

    //client_handshake_thread.join();
    //server_handshake_thread.join();
    
    print_many_bytes(server_handshake_traffic_secret, 32);
	finalize_plain_prot();
}

// Application
void DeriveMasterSecret() {
	setup_plain_prot(true, "DeriveMasterSecret.txt");

    unsigned char test_handshake_secret1[]=
			{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

    unsigned char test_output_mask_1[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5,
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5
            };
    
    unsigned char test_handshake_secret2[] =
            {
                    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 
                    0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01, 
                    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
                    0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac 
            };
    
    unsigned char test_output_mask_2[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcf, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa3,
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5
            };

    unsigned char empty_hash[] =
			{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
			};

	block one = CircuitExecution::circ_exec->public_label(true);
	block zero = CircuitExecution::circ_exec->public_label(false);

	bool key_plaintext1[256];
	for (int i = 0; i < 32; i++) {
		int w = test_handshake_secret1[i];
		for (int j = 0; j < 8; j++) {
			key_plaintext1[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask1[256];
    for (int i = 0; i < 32; i++) {
		int w = test_output_mask_1[i];
		for (int j = 0; j < 8; j++) {
			outputmask1[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

    bool key_plaintext2[256];
	for (int i = 0; i < 32; i++) {
		int w = test_handshake_secret2[i];
		for (int j = 0; j < 8; j++) {
			key_plaintext2[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask2[256];
    for (int i = 0; i < 32; i++) {
		int w = test_output_mask_2[i];
		for (int j = 0; j < 8; j++) {
			outputmask2[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

	block context[256];
	for (int i = 0; i < 32; i++) {
		int w = empty_hash[i];
		for (int j = 0; j < 8; j++) {
			context[i * 8 + j] = w & 1 ? one : zero;
			w >>= 1;
		}
	}

	block key1[256];
	ProtocolExecution::prot_exec->feed(key1, ALICE, key_plaintext1, 256);
    
    block output_mask1[256];
    ProtocolExecution::prot_exec->feed(output_mask1, ALICE, outputmask1, 256);
    
    block key2[256];
	ProtocolExecution::prot_exec->feed(key2, BOB, key_plaintext2, 256);
    
    block output_mask2[256];
    ProtocolExecution::prot_exec->feed(output_mask2, BOB, outputmask2, 256);
    
    block key[256];
    xor_256_bits(key1, key2, key);
	
    block derived_secret[256];
	hkdf_expand_label(key, 256, "derived", context, 256, derived_secret, 32);

	block zero_key[256];
	for (int i = 0; i < 256; i++) {
		zero_key[i] = zero;
	}
    
	block master_secret[256];
	hkdf_extract(derived_secret, 256, zero_key, 256, master_secret);
    block master_secret_share1[256];
    block master_secret_share2[256];
    create_256bit_shares(master_secret, master_secret_share1, master_secret_share2);
    block output1[256];
    xor_256_bits(master_secret_share1, output_mask1, output1);
    block output2[256];
    xor_256_bits(master_secret_share2, output_mask2, output2);
    print_hash(output1);
    print_hash(output2);
    finalize_plain_prot();
}

void DeriveClientApplicationSecret() {
	setup_plain_prot(true, "DeriveClientApplicationSecret.txt");

    unsigned char test_master_secret1[]=
			{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

    unsigned char handshake_hash_test_data[] =
			{
					0x96, 0x08, 0x10, 0x2a, 0x0f, 0x1c, 0xcc, 0x6d,
					0xb6, 0x25, 0x0b, 0x7b, 0x7e, 0x41, 0x7b, 0x1a,
					0x00, 0x0e, 0xaa, 0xda, 0x3d, 0xaa, 0xe4, 0x77,
					0x7a, 0x76, 0x86, 0xc9, 0xff, 0x83, 0xdf, 0x13
			};

    unsigned char test_output_mask_1[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5,
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5
            };
    
    unsigned char test_master_secret2[] =
            {
                    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 
                    0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01, 
                    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
                    0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac 
            };
    
    unsigned char test_output_mask_2[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcf, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa3,
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5
            };

	bool master_secret1[256];
	for (int i = 0; i < 32; i++) {
		int w = test_master_secret1[i];
		for (int j = 0; j < 8; j++) {
			master_secret1[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool handshake_hash_plaintext[256];
	for (int i = 0; i < 32; i++) {
		int w = handshake_hash_test_data[i];
		for (int j = 0; j < 8; j++) {
			handshake_hash_plaintext[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask1[256];
    for (int i = 0; i < 32; i++) {
		int w = test_output_mask_1[i];
		for (int j = 0; j < 8; j++) {
			outputmask1[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

    bool master_secret2[256];
	for (int i = 0; i < 32; i++) {
		int w = test_master_secret2[i];
		for (int j = 0; j < 8; j++) {
			master_secret2[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask2[256];
    for (int i = 0; i < 32; i++) {
		int w = test_output_mask_2[i];
		for (int j = 0; j < 8; j++) {
			outputmask2[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

	block mastersecret1[256];
	ProtocolExecution::prot_exec->feed(mastersecret1, ALICE, master_secret1, 256);
    
    block handshake_hash[256];
	ProtocolExecution::prot_exec->feed(handshake_hash, ALICE, handshake_hash_plaintext, 256);

    block output_mask1[256];
    ProtocolExecution::prot_exec->feed(output_mask1, ALICE, outputmask1, 256);
    
    block mastersecret2[256];
	ProtocolExecution::prot_exec->feed(mastersecret2, BOB, master_secret2, 256);
    
    block output_mask2[256];
    ProtocolExecution::prot_exec->feed(output_mask2, BOB, outputmask2, 256);
    
    block master_secret[256];
    xor_256_bits(mastersecret1, mastersecret2, master_secret);
	
    // client_application_traffic_secret = HKDF-Expand-Label(
	//    key = master_secret,
	//    label = "c ap traffic",
	//    context = handshake_hash,
	//    len = 32)

    block client_application_traffic_secret[256];
    // We are only parallelizing only the compilation, not really the circuit, unfortunately.
    //std::thread client_thread([&]() {
        hkdf_expand_label(master_secret, 256, "c ap traffic", handshake_hash, 256, client_application_traffic_secret, 32);
    //});
    block client_application_traffic_secret_share1[256];
    block client_application_traffic_secret_share2[256];
    create_256bit_shares(client_application_traffic_secret, client_application_traffic_secret_share1, client_application_traffic_secret_share2);
    block output1[256];
    xor_256_bits(client_application_traffic_secret_share1, output_mask1, output1);
    block output2[256];
    xor_256_bits(client_application_traffic_secret_share2, output_mask2, output2);
    print_hash(output1);
    print_hash(output2);
    finalize_plain_prot();
}

void DeriveServerApplicationSecret() {
	setup_plain_prot(true, "DeriveServerApplicationSecret.txt");

    unsigned char test_master_secret1[]=
			{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

    unsigned char handshake_hash_test_data[] =
			{
					0x96, 0x08, 0x10, 0x2a, 0x0f, 0x1c, 0xcc, 0x6d,
					0xb6, 0x25, 0x0b, 0x7b, 0x7e, 0x41, 0x7b, 0x1a,
					0x00, 0x0e, 0xaa, 0xda, 0x3d, 0xaa, 0xe4, 0x77,
					0x7a, 0x76, 0x86, 0xc9, 0xff, 0x83, 0xdf, 0x13
			};

    unsigned char test_output_mask_1[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5,
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5
            };
    
    unsigned char test_master_secret2[] =
            {
                    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 
                    0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01, 
                    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
                    0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac 
            };
    
    unsigned char test_output_mask_2[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcf, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa3,
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5
            };

	bool master_secret1[256];
	for (int i = 0; i < 32; i++) {
		int w = test_master_secret1[i];
		for (int j = 0; j < 8; j++) {
			master_secret1[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool handshake_hash_plaintext[256];
	for (int i = 0; i < 32; i++) {
		int w = handshake_hash_test_data[i];
		for (int j = 0; j < 8; j++) {
			handshake_hash_plaintext[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask1[256];
    for (int i = 0; i < 32; i++) {
		int w = test_output_mask_1[i];
		for (int j = 0; j < 8; j++) {
			outputmask1[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

    bool master_secret2[256];
	for (int i = 0; i < 32; i++) {
		int w = test_master_secret2[i];
		for (int j = 0; j < 8; j++) {
			master_secret2[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask2[256];
    for (int i = 0; i < 32; i++) {
		int w = test_output_mask_2[i];
		for (int j = 0; j < 8; j++) {
			outputmask2[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

	block mastersecret1[256];
	ProtocolExecution::prot_exec->feed(mastersecret1, ALICE, master_secret1, 256);
    
    block handshake_hash[256];
	ProtocolExecution::prot_exec->feed(handshake_hash, ALICE, handshake_hash_plaintext, 256);

    block output_mask1[256];
    ProtocolExecution::prot_exec->feed(output_mask1, ALICE, outputmask1, 256);
    
    block mastersecret2[256];
	ProtocolExecution::prot_exec->feed(mastersecret2, BOB, master_secret2, 256);
    
    block output_mask2[256];
    ProtocolExecution::prot_exec->feed(output_mask2, BOB, outputmask2, 256);
    
    block master_secret[256];
    xor_256_bits(mastersecret1, mastersecret2, master_secret);
	
    // client_application_traffic_secret = HKDF-Expand-Label(
	//    key = master_secret,
	//    label = "c ap traffic",
	//    context = handshake_hash,
	//    len = 32)

    block server_application_traffic_secret[256];
    // We are only parallelizing only the compilation, not really the circuit, unfortunately.
    //std::thread client_thread([&]() {
        hkdf_expand_label(master_secret, 256, "s ap traffic", handshake_hash, 256, server_application_traffic_secret, 32);
    //});
    block server_application_traffic_secret_share1[256];
    block server_application_traffic_secret_share2[256];
    create_256bit_shares(server_application_traffic_secret, server_application_traffic_secret_share1, server_application_traffic_secret_share2);
    block output1[256];
    xor_256_bits(server_application_traffic_secret_share1, output_mask1, output1);
    block output2[256];
    xor_256_bits(server_application_traffic_secret_share2, output_mask2, output2);
    print_hash(output1);
    print_hash(output2);
    finalize_plain_prot();
}

void DeriveClientApplicationKey() {
	setup_plain_prot(true, "DeriveClientApplicationKey.txt");

    unsigned char test_client_secret1[]=
			{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

    unsigned char test_output_mask_1[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa5
            };
    
    unsigned char test_client_secret2[] =
            {
                    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 
                    0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01, 
                    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
                    0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac 
            };
    
    unsigned char test_output_mask_2[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcf, 0xcd, 0xfa, 0xb2, 0xb7, 0xaa, 0xa3
            };

	bool client_secret1[256];
	for (int i = 0; i < 32; i++) {
		int w = test_client_secret1[i];
		for (int j = 0; j < 8; j++) {
			client_secret1[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask1[128];
    for (int i = 0; i < 16; i++) {
		int w = test_output_mask_1[i];
		for (int j = 0; j < 8; j++) {
			outputmask1[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

    bool client_secret2[256];
	for (int i = 0; i < 32; i++) {
		int w = test_client_secret2[i];
		for (int j = 0; j < 8; j++) {
			client_secret2[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask2[128];
    for (int i = 0; i < 16; i++) {
		int w = test_output_mask_2[i];
		for (int j = 0; j < 8; j++) {
			outputmask2[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

	block clientsecret1[256];
	ProtocolExecution::prot_exec->feed(clientsecret1, ALICE, client_secret1, 256);
    
    block output_mask1[128];
    ProtocolExecution::prot_exec->feed(output_mask1, ALICE, outputmask1, 128);
    
    block clientsecret2[256];
	ProtocolExecution::prot_exec->feed(clientsecret2, BOB, client_secret2, 256);
    
    block output_mask2[128];
    ProtocolExecution::prot_exec->feed(output_mask2, BOB, outputmask2, 128);
    
    block client_application_traffic_secret[256];
    xor_256_bits(clientsecret1, clientsecret2, client_application_traffic_secret);

    // client_application_key = HKDF-Expand-Label(
	//    key = client_application_traffic_secret,
	//    label = "key",
	//    context = "",
	//    len = 16)

    block client_application_key[128];
	//std::thread key_thread([&]() {
        hkdf_expand_label(client_application_traffic_secret, 256, "key", NULL, 0, client_application_key, 16);
    //});

    block client_application_key_share1[128];
    block client_application_key_share2[128];
    create_128bit_shares(client_application_key, client_application_key_share1, client_application_key_share2);
    
	block output1[128];
    block output2[128];
    xor_128_bits(client_application_key_share1, output_mask1, output1);
    xor_128_bits(client_application_key_share2, output_mask2, output2);

    print_many_bytes(output1, 16);
    print_many_bytes(output2, 16);
    finalize_plain_prot();
}

void DeriveClientApplicationIV() {
	setup_plain_prot(true, "DeriveClientApplicationIV.txt");

    unsigned char test_client_secret1[]=
			{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

    unsigned char test_output_mask_1[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcc, 0xcd, 0xfa
            };
    
    unsigned char test_client_secret2[] =
            {
                    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 
                    0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01, 
                    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
                    0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac 
            };
    
    unsigned char test_output_mask_2[] = 
            {
                    0xff, 0x34, 0x28, 0x91, 0xd3, 0x21, 0x00, 0x40,
                    0xdd, 0xcf, 0xcd, 0xfa
            };

	bool client_secret1[256];
	for (int i = 0; i < 32; i++) {
		int w = test_client_secret1[i];
		for (int j = 0; j < 8; j++) {
			client_secret1[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask1[96];
    for (int i = 0; i < 12; i++) {
		int w = test_output_mask_1[i];
		for (int j = 0; j < 8; j++) {
			outputmask1[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

    bool client_secret2[256];
	for (int i = 0; i < 32; i++) {
		int w = test_client_secret2[i];
		for (int j = 0; j < 8; j++) {
			client_secret2[i * 8 + j] = w & 1;
			w >>= 1;
		}
	}

    bool outputmask2[96];
    for (int i = 0; i < 12; i++) {
		int w = test_output_mask_2[i];
		for (int j = 0; j < 8; j++) {
			outputmask2[i * 8 + j] = (w & 1) != 0;
			w >>= 1;
		}
	}

	block clientsecret1[256];
	ProtocolExecution::prot_exec->feed(clientsecret1, ALICE, client_secret1, 256);
    
    block output_mask1[96];
    ProtocolExecution::prot_exec->feed(output_mask1, ALICE, outputmask1, 96);
    
    block clientsecret2[256];
	ProtocolExecution::prot_exec->feed(clientsecret2, BOB, client_secret2, 256);
    
    block output_mask2[96];
    ProtocolExecution::prot_exec->feed(output_mask2, BOB, outputmask2, 96);
    
    block client_application_traffic_secret[256];
    xor_256_bits(clientsecret1, clientsecret2, client_application_traffic_secret);

    // client_application_iv = HKDF-Expand-Label(
	//    key = client_application_traffic_secret,
	//    label = "iv",
	//    context = "",
	//    len = 12)

    block client_application_iv[96];
	//std::thread iv_thread([&]() {
        hkdf_expand_label(client_application_traffic_secret, 256, "iv", NULL, 0, client_application_iv, 12);
    //});
    
    block client_application_iv_share1[128];
    block client_application_iv_share2[128];
    create_96bit_shares(client_application_iv, client_application_iv_share1, client_application_iv_share2);
    
	block output1[128];
    block output2[128];
    xor_96_bits(client_application_iv_share1, output_mask1, output1);
    xor_96_bits(client_application_iv_share2, output_mask2, output2);

    print_many_bytes(output1, 12);
    print_many_bytes(output2, 12);
    finalize_plain_prot();
}

// Encryption
void aes_128_gcm_encrypt(block *aad, int aad_len, block *iv, int iv_len, block *key, int key_len, block *plaintext, int plaintext_len, 
block *ciphertext, int ciphertext_len, block *tag, int tag_len){
    
    block input[776];
    for (int i = 0; i < aad_len; i++){
        input[i] = aad[i];
    }
    for (int i = 0; i < iv_len; i++){
        input[i+aad_len] = iv[i];
    }
    for (int i = 0; i < key_len; i++){
        input[i+aad_len+iv_len] = key[i];
    }
    for (int i = 0; i < plaintext_len; i++){
        input[i+aad_len+iv_len+key_len] = plaintext[i];
    }
    block output[640];
    BristolFormat bf("aes-128-gcm-512-bit-plaintext-40-bit-aad.txt");
    bf.compute(output, input, input);

    for (int i = 0; i < ciphertext_len; i++){
        ciphertext[i] = output[i];
    }
    for (int i = 0; i < tag_len; i++){
        tag[i] = output[i+ciphertext_len];
    }
}

void DeriveSMTPRCPTTOCommandCiphertext(){
    setup_plain_prot(true, "DeriveSMTPRCPTTOCommandCiphertext.txt");

    unsigned char test_aad[] = {
        0x17, 0x03, 0x03, 0x00, 0x15
    };

    unsigned char test_iv[] = {
        0x01, 0x6d, 0xbb, 0x38, 
        0xda, 0xa7, 0x6d, 0xfe,
        0xf1, 0x24, 0x03, 0x64
    };

    unsigned char test_key_share1[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char test_email_share1[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //<email address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cannot be
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // longer than
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 52 chars> this can accomodate 95% email addresses in world
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fill  
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // with
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00              // white space
    };

    unsigned char test_key_share2[] = {
        0x01, 0x6d, 0xbb, 0x38, 0xda, 0xa7, 0x6d, 0xfe,
		0x7d, 0xa3, 0x84, 0xeb, 0xf1, 0x24, 0x03, 0x64
    };

    unsigned char test_email_share2[] = {
        0x3c, 0x62, 0x62, 0x62, 0x65, 0x6c, 0x63, 0x68, //<email address
        0x40, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2d, // cannot be
        0x6c, 0x65, 0x76, 0x65, 0x6c, 0x2e, 0x63, 0x6f, // longer than
        0x6d, 0x3e, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // 52 chars> this can accomodate 95% email addresses in world
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // fill  
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // with
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20              // white space
    };

    unsigned char test_command[] = {    
        0x52, 0x43, 0x50, 0x54, 0x20, 0x54, 0x4f, 0x3a, //RCPT TO:
    };
    
    unsigned char test_crlf[] = {
        0x0d, 0x0a  //\r\n
    };

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

    bool test_key_input1[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key_share1[i];
        for (int j = 0; j < 8; j++) {
            test_key_input1[(15-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_email_share_input1[54 * 8];
    for (int i = 0; i < 54; i++) {
        int w = test_email_share1[i];
        for (int j = 0; j < 8; j++) {
            test_email_share_input1[i * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_key_input2[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key_share2[i];
        for (int j = 0; j < 8; j++) {
            test_key_input2[(15-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_email_share_input2[54 * 8];
    for (int i = 0; i < 54; i++) {
        int w = test_email_share2[i];
        for (int j = 0; j < 8; j++) {
            test_email_share_input2[i * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    block one = CircuitExecution::circ_exec->public_label(true);
	block zero = CircuitExecution::circ_exec->public_label(false);

    block command[8*8];
	for (int i = 0; i < 8; i++) {
		int w = test_command[i];
		for (int j = 0; j < 8; j++) {
			command[i * 8 + j] = w & 1 ? one : zero;
			w >>= 1;
		}
	}

    block crlf[2*8];
	for (int i = 0; i < 2; i++) {
		int w = test_crlf[i];
		for (int j = 0; j < 8; j++) {
			crlf[i * 8 + j] = w & 1 ? one : zero;
			w >>= 1;
		}
	}

    block aad[5*8];
    block iv[12*8];
    block key1[16*8];
    block email_share1[54*8];
    ProtocolExecution::prot_exec->feed(aad, ALICE, test_aad_input, 5 * 8);
    ProtocolExecution::prot_exec->feed(iv, ALICE, test_iv_input, 12 * 8);
    ProtocolExecution::prot_exec->feed(key1, ALICE, test_key_input1, 16 * 8);
    ProtocolExecution::prot_exec->feed(email_share1, ALICE, test_email_share_input1, 54 * 8);
    block key2[16*8];
    block email_share2[54*8];
    ProtocolExecution::prot_exec->feed(key2, BOB, test_key_input2, 16 * 8);
    ProtocolExecution::prot_exec->feed(email_share2, BOB, test_email_share_input2, 54 * 8);

    block key[16*8];
    xor_128_bits(key1, key2, key);
    block email[54*8];
    xor_432_bits(email_share1, email_share2, email);

    block plaintext[512];
    for(int i = 0; i < 8*8; i++){
        plaintext[i] = command[i];
    }
    for(int i = 0; i < 54*8; i++){
        plaintext[i + 8*8] = email[i];
    }
    for(int i = 0; i < 2*8; i++){
        plaintext[i + 8*8 + 54*8] = crlf[i];
    }
    
    block ciphertext[64*8];
    block tag[16*8];
    aes_128_gcm_encrypt(aad, 5*8, iv, 12*8, key, 16*8, plaintext, 64*8, ciphertext, 64*8, tag, 16*8);

    print_many_bytes(ciphertext, 64);
    print_many_bytes(tag, 16);
    finalize_plain_prot();
}

void DeriveSMTPTOCommandCiphertext(){
    setup_plain_prot(true, "DeriveSMTPTOCommandCiphertext.txt");
    unsigned char test_aad[] = {
        0x17, 0x03, 0x03, 0x00, 0x15
    };

    unsigned char test_iv[] = {
        0x01, 0x6d, 0xbb, 0x38, 
        0xda, 0xa7, 0x6d, 0xfe,
        0xf1, 0x24, 0x03, 0x64
    };

    unsigned char test_key_share1[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char test_email_share1[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //<email address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cannot be
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // longer than
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 52 chars> this can accomodate 95% email addresses in world
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fill  
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // with
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00              // white space
    };

    unsigned char test_key_share2[] = {
        0x01, 0x6d, 0xbb, 0x38, 0xda, 0xa7, 0x6d, 0xfe,
		0x7d, 0xa3, 0x84, 0xeb, 0xf1, 0x24, 0x03, 0x64
    };

    unsigned char test_email_share2[] = {
        0x3c, 0x62, 0x62, 0x62, 0x65, 0x6c, 0x63, 0x68, //<email address
        0x40, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2d, // cannot be
        0x6c, 0x65, 0x76, 0x65, 0x6c, 0x2e, 0x63, 0x6f, // longer than
        0x6d, 0x3e, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // 52 chars> this can accomodate 95% email addresses in world
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // fill  
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // with
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20              // white space
    };

    unsigned char test_command[] = {    
        0x54, 0x6f, 0x3a, 0x20, 0x20, 0x20, 0x20, 0x20, //To: fill with white space
    };
    
    unsigned char test_crlf[] = {
        0x0d, 0x0a  //\r\n
    };

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

    bool test_key_input1[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key_share1[i];
        for (int j = 0; j < 8; j++) {
            test_key_input1[(15-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_email_share_input1[54 * 8];
    for (int i = 0; i < 54; i++) {
        int w = test_email_share1[i];
        for (int j = 0; j < 8; j++) {
            test_email_share_input1[i * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_key_input2[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key_share2[i];
        for (int j = 0; j < 8; j++) {
            test_key_input2[(15-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_email_share_input2[54 * 8];
    for (int i = 0; i < 54; i++) {
        int w = test_email_share2[i];
        for (int j = 0; j < 8; j++) {
            test_email_share_input2[i * 8 + j] = w & 1;
            w >>= 1;
        }
    }


    block one = CircuitExecution::circ_exec->public_label(true);
	block zero = CircuitExecution::circ_exec->public_label(false);

    block command[8*8];
	for (int i = 0; i < 8; i++) {
		int w = test_command[i];
		for (int j = 0; j < 8; j++) {
			command[i * 8 + j] = w & 1 ? one : zero;
			w >>= 1;
		}
	}

    block crlf[2*8];
	for (int i = 0; i < 2; i++) {
		int w = test_crlf[i];
		for (int j = 0; j < 8; j++) {
			crlf[i * 8 + j] = w & 1 ? one : zero;
			w >>= 1;
		}
	}

    block aad[5*8];
    block iv[12*8];
    block key1[16*8];
    block email_share1[54*8];
    ProtocolExecution::prot_exec->feed(aad, ALICE, test_aad_input, 5 * 8);
    ProtocolExecution::prot_exec->feed(iv, ALICE, test_iv_input, 12 * 8);
    ProtocolExecution::prot_exec->feed(key1, ALICE, test_key_input1, 16 * 8);
    ProtocolExecution::prot_exec->feed(email_share1, ALICE, test_email_share_input1, 54 * 8);
    block key2[16*8];
    block email_share2[54*8];
    ProtocolExecution::prot_exec->feed(key2, BOB, test_key_input2, 16 * 8);
    ProtocolExecution::prot_exec->feed(email_share2, BOB, test_email_share_input2, 54 * 8);

    block key[16*8];
    xor_128_bits(key1, key2, key);
    block email[54*8];
    xor_432_bits(email_share1, email_share2, email);

    block plaintext[512];
    for(int i = 0; i < 8*8; i++){
        plaintext[i] = command[i];
    }
    for(int i = 0; i < 54*8; i++){
        plaintext[i + 8*8] = email[i];
    }
    for(int i = 0; i < 2*8; i++){
        plaintext[i + 8*8 + 54*8] = crlf[i];
    }
    
    block ciphertext[64*8];
    block tag[16*8];
    aes_128_gcm_encrypt(aad, 5*8, iv, 12*8, key, 16*8, plaintext, 64*8, ciphertext, 64*8, tag, 16*8);

    print_many_bytes(ciphertext, 64);
    print_many_bytes(tag, 16);
    finalize_plain_prot();
}

void DeriveTLSCiphertext(){
    setup_plain_prot(true, "DeriveTLSCiphertext.txt");
    unsigned char test_aad[] = {
        0x17, 0x03, 0x03, 0x00, 0x15
    };

    unsigned char test_iv[] = {
        0x01, 0x6d, 0xbb, 0x38, 
        0xda, 0xa7, 0x6d, 0xfe,
        0xf1, 0x24, 0x03, 0x64
    };

    unsigned char test_key1[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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

    unsigned char test_key2[] = {
        0x01, 0x6d, 0xbb, 0x38, 0xda, 0xa7, 0x6d, 0xfe,
		0x7d, 0xa3, 0x84, 0xeb, 0xf1, 0x24, 0x03, 0x64
    };

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

    bool test_key_input1[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key1[i];
        for (int j = 0; j < 8; j++) {
            test_key_input1[(15-i) * 8 + j] = w & 1;
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
    
    bool test_key_input2[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key2[i];
        for (int j = 0; j < 8; j++) {
            test_key_input2[(15-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }
    // create inputs for circuit
    block aad[5*8];
    block iv[12*8];
    block key1[16*8];
    block plaintext[64*8];
    ProtocolExecution::prot_exec->feed(aad, ALICE, test_aad_input, 5 * 8);
    ProtocolExecution::prot_exec->feed(iv, ALICE, test_iv_input, 12 * 8);
    ProtocolExecution::prot_exec->feed(key1, ALICE, test_key_input1, 16 * 8);
    ProtocolExecution::prot_exec->feed(plaintext, ALICE, test_plaintext_input, 64 * 8);
    block key2[16*8];
    ProtocolExecution::prot_exec->feed(key2, BOB, test_key_input2, 16 * 8);

    block key[16*8];
    xor_128_bits(key1, key2, key);
    block ciphertext[64*8];
    block tag[16*8];
    aes_128_gcm_encrypt(aad, 5*8, iv, 12*8, key, 16*8, plaintext, 64*8, ciphertext, 64*8, tag, 16*8);

    print_many_bytes(ciphertext, 64);
    print_many_bytes(tag, 16);
    finalize_plain_prot();
}

void DeriveTLSSharedPlaintextCiphertext(){
    setup_plain_prot(true, "DeriveTLSSharedPlaintextCiphertext.txt");
    unsigned char test_aad[] = {
        0x17, 0x03, 0x03, 0x00, 0x15
    };

    unsigned char test_iv[] = {
        0x01, 0x6d, 0xbb, 0x38, 
        0xda, 0xa7, 0x6d, 0xfe,
        0xf1, 0x24, 0x03, 0x64
    };

    unsigned char test_key1[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
   
    unsigned char test_plaintext1[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  
    };

    unsigned char test_key2[] = {
        0x01, 0x6d, 0xbb, 0x38, 0xda, 0xa7, 0x6d, 0xfe,
		0x7d, 0xa3, 0x84, 0xeb, 0xf1, 0x24, 0x03, 0x64
    };

    unsigned char test_plaintext2[] = {
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

    bool test_key_input1[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key1[i];
        for (int j = 0; j < 8; j++) {
            test_key_input1[(15-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_plaintext_input1[64 * 8];
    for (int i = 0; i < 64; i++) {
        int w = test_plaintext1[i];
        for (int j = 0; j < 8; j++) {
            test_plaintext_input1[i * 8 + j] = w & 1;
            w >>= 1;
        }
    }
    
    bool test_key_input2[16 * 8];
    for (int i = 0; i < 16; i++) {
        int w = test_key2[i];
        for (int j = 0; j < 8; j++) {
            test_key_input2[(15-i) * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    bool test_plaintext_input2[64 * 8];
    for (int i = 0; i < 64; i++) {
        int w = test_plaintext2[i];
        for (int j = 0; j < 8; j++) {
            test_plaintext_input2[i * 8 + j] = w & 1;
            w >>= 1;
        }
    }

    // create inputs for circuit
    block aad[5*8];
    block iv[12*8];
    block key1[16*8];
    block plaintext1[64*8];
    ProtocolExecution::prot_exec->feed(aad, ALICE, test_aad_input, 5 * 8);
    ProtocolExecution::prot_exec->feed(iv, ALICE, test_iv_input, 12 * 8);
    ProtocolExecution::prot_exec->feed(key1, ALICE, test_key_input1, 16 * 8);
    ProtocolExecution::prot_exec->feed(plaintext1, ALICE, test_plaintext_input1, 64 * 8);
    block key2[16*8];
    ProtocolExecution::prot_exec->feed(key2, BOB, test_key_input2, 16 * 8);
    block plaintext2[64*8];
    ProtocolExecution::prot_exec->feed(plaintext2, BOB, test_plaintext_input2, 64 * 8);

    block key[16*8];
    xor_128_bits(key1, key2, key);
    block plaintext[64*8];
    xor_512_bits(plaintext1, plaintext2, plaintext);

    block ciphertext[64*8];
    block tag[16*8];
    aes_128_gcm_encrypt(aad, 5*8, iv, 12*8, key, 16*8, plaintext, 64*8, ciphertext, 64*8, tag, 16*8);

    print_many_bytes(ciphertext, 64);
    print_many_bytes(tag, 16);
    finalize_plain_prot();
}

int main(int argc, char **argv) {
	printf("Handshake Secret Shares:\n");
    DeriveHandshakeSecret_PreMasterSecret();
    printf("Server Handshake Secret and Client Handshake Secret:\n");
	DeriveClientHandshakeSecret();
    DeriveServerHandshakeSecret();
    printf("Client Application Key shares, Client Application IV, Server Application Secret:\n");
    DeriveClientApplicationSecret();
    DeriveClientApplicationKey();
    DeriveClientApplicationIV();
    DeriveServerApplicationSecret();
    printf("SMTP Encrypted RCPT TO:<email-id>\\r\\n command:\n");
    DeriveSMTPRCPTTOCommandCiphertext();
    printf("SMTP Encrypted TO:<email-id>\\r\\n command:\n");
    DeriveSMTPTOCommandCiphertext();
    printf("Encrypted TLS ciphertext using shared keys:\n");
    DeriveTLSCiphertext();
    printf("Encrypted TLS ciphertext using shared keys and shared plaintext:\n");
    DeriveTLSSharedPlaintextCiphertext();
	return 0;
}
