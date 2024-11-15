#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "relic/relic.h"
#include "pari/pari.h"
#include "zmq.h"
#include "bob.h"
#include "types.h"
#include "util.h"
#include "gmp.h"

unsigned PROMISE_COMPLETED;
unsigned PUZZLE_SHARED;
unsigned PUZZLE_SOLVED;
unsigned TOKEN_RECEIVED;

int get_message_type(char *key) {
  for (size_t i = 0; i < TOTAL_MESSAGES; i++) {
    symstruct_t sym = msg_lookuptable[i];
    if (strcmp(sym.key, key) == 0) {
      return sym.code;
    }
  }
  return -1;
}

msg_handler_t get_message_handler(char *key) {
  switch (get_message_type(key))
  {
    case TOKEN_SHARE:
      return token_share_handler;
    
    case PROMISE_COM:
      return promise_com_handler;

    case PROMISE_DECOM:
      return promise_decom_handler;

    case PROMISE_OVER:
      return promise_over_handler;

    case PUZZLE_SHARE_DONE:
      return puzzle_share_done_handler;

    case PUZZLE_SOLUTION_SHARE:
      return puzzle_solution_share_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(bob_state_t state, void *socket, zmq_msg_t message) {
  int result_status = RLC_OK;

  message_t msg;
  message_null(msg);

  RLC_TRY {
    printf("Received message size: %ld bytes\n", zmq_msg_size(&message));
    deserialize_message(&msg, (uint8_t *) zmq_msg_data(&message));

    printf("Executing %s...\n", msg->type);
    msg_handler_t msg_handler = get_message_handler(msg->type);
    if (msg_handler(state, socket, msg->data) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    printf("Finished executing %s.\n\n", msg->type);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (msg != NULL) message_free(msg);
  }

  return result_status;
}

int receive_message(bob_state_t state, void *socket) {
  int result_status = RLC_OK;

  zmq_msg_t message;

  RLC_TRY {
    int rc = zmq_msg_init(&message);
    if (rc != 0) {
      fprintf(stderr, "Error: could not initialize the message.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    rc = zmq_msg_recv(&message, socket, ZMQ_DONTWAIT);
    if (rc != -1 && handle_message(state, socket, message) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    zmq_msg_close(&message);
  }

  return result_status;
}

int token_share_handler(bob_state_t state, void *socet, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  RLC_TRY {    
    // Deserialize the data from the message.
    bn_read_bin(state->tid, data, RLC_BN_SIZE);
    g1_read_bin(state->sigma_tid->sigma_1, data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(state->sigma_tid->sigma_2, data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);
    bn_read_bin(state->lhtlp_param->T, data + RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED, RLC_BN_SIZE);
    bn_read_bin(state->lhtlp_param->N, data + 2 * RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED, BYTES_MODULUS_RSA);
    bn_read_bin(state->lhtlp_param->g, data + 2 * RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED + BYTES_MODULUS_RSA, BYTES_MODULUS_RSA);
    bn_read_bin(state->lhtlp_param->h, data + 2 * RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED + 2 * BYTES_MODULUS_RSA, BYTES_MODULUS_RSA);

    TOKEN_RECEIVED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  }

  return result_status;
}

int promise_init(bob_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  size_t v_bytes;  
  message_t promise_init_msg;
  
  const unsigned SERIALIZED_LEN = (BITS_STATISTIC_PARAM+2) * RLC_EC_SIZE_COMPRESSED + (2 * BITS_STATISTIC_PARAM + 2) * BYTES_MODULUS_RSA + (2 * BITS_STATISTIC_PARAM + 2) * BYTES_MODULUS_RSA_2 + (BITS_STATISTIC_PARAM + 1) * BYTES_INTERVAL_EXT_PARAM_PUB + BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W + BYTES_MODULUS_RSA_POWER;
	size_t v_bytes1, v_bytes2;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];
  char bin_from_hash[BITS_SHA_256 + 1];
  char bin_sub_threshold[BITS_THRESHOLD_PARAM - 1];
  uint8_t byte_sub_threshold[BYTES_THRESHOLD_LEN_PARAM];

  bn_t q, g_inter_prime, N_2, rand_ex, h_rand_ex, exp, N_plus_1, N_plus_1_sk, interval_B;     
  bn_t sk_b, interval_L, e;
  cl_ciphertext_t ctx_sk_from_b;
  bn_t sk_shares[BITS_STATISTIC_PARAM];
  bn_t lagrange_bases[BITS_STATISTIC_PARAM];
  bn_t rands[BITS_STATISTIC_PARAM];
  ec_t pk_shares[BITS_STATISTIC_PARAM];
  lhtlp_puzzle_t puzzles[BITS_STATISTIC_PARAM];
  pis_lhtlp_range_t lhtlp_ranges;
  lhtlp_param_t lhtlp_param;
  lhtlp_puzzle_t puzzle;  
  
  polynomial_param_t polyfunc;
  message_null(promise_init_msg);
  bn_null(q);

  bn_null(N_2);
  bn_null(g_inter_prime);
  bn_null(rand_ex);
  bn_null(h_rand_ex);
  bn_null(exp);
  bn_null(N_plus_1);
  bn_null(N_plus_1_sk);
  bn_null(interval_B);
  bn_null(sk_b);
  bn_null(interval_L);
  bn_null(e);
  cl_ciphertext_null(ctx_sk_from_b);
  lhtlp_param_null(lhtlp_param);
  lhtlp_puzzle_null(puzzle);
  polynomial_param_null(polyfunc);
  pis_lhtlp_range_null(lhtlp_ranges);

  for(int i=0; i<BITS_STATISTIC_PARAM; i++)
  {
    bn_null(sk_shares[i]);
    bn_null(lagrange_bases[i]);
    bn_null(rands[i]);
    ec_null(pk_shares[i]);
    lhtlp_puzzle_null(puzzles[i]);    
  }

  RLC_TRY {

    bn_new(q);
    bn_new(N_2);
    bn_new(g_inter_prime);
    bn_new(rand_ex);
    bn_new(h_rand_ex);
    bn_new(exp);
    bn_new(N_plus_1);
    bn_new(N_plus_1_sk);
    bn_new(interval_B);
    bn_new(sk_b);
    bn_new(interval_L);
    bn_new(e);
    cl_ciphertext_new(ctx_sk_from_b);
    lhtlp_param_new(lhtlp_param);
    lhtlp_puzzle_new(puzzle);
    pis_lhtlp_range_new(lhtlp_ranges, BITS_STATISTIC_PARAM);    
    for(int i=0; i<BITS_STATISTIC_PARAM; i++)
    {
      bn_new(sk_shares[i]);
      bn_new(lagrange_bases[i]);
      bn_new(rands[i]);
      ec_new(pk_shares[i]);
      lhtlp_puzzle_new(puzzles[i]);
      lhtlp_puzzle_new(lhtlp_ranges->Ds[i]);
      bn_new(lhtlp_ranges->Vs[i]);
      bn_new(lhtlp_ranges->Ws[i]);
    }
    polynomial_param_new(polyfunc, DEGREE_PARAM);
    bn_set_2b(interval_L, BITS_INTERVAL_PARAM_PUB);
    ec_curve_get_ord(q);
    polyfunc_gen(polyfunc, DEGREE_PARAM, state->bob_ec_sk->sk, q);    

    bn_mul(N_2, state->lhtlp_param->N, state->lhtlp_param->N);
    for(int i=0; i<BITS_STATISTIC_PARAM; i++)
    {
      polyfunc_eval(sk_shares[i], polyfunc, i + 1, q);
      ec_mul_gen(pk_shares[i], sk_shares[i]);
      bn_rand_mod(rands[i], N_2);
      if (lhtlp_puzzle_gen(puzzles[i], state->lhtlp_param, sk_shares[i], rands[i], EXTEND_S) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }    
    }

    if (pi_lhtlp_range_gen(lhtlp_ranges, puzzles, state->lhtlp_param, sk_shares, rands, BITS_STATISTIC_PARAM, N_2, interval_L) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }      
    // Compute CL encryption secret/public key pair for the bob.
		state->bob_cl_sk->sk = randomi(state->cl_params->bound);
		state->bob_cl_pk->pk = nupow(state->cl_params->g_q, state->bob_cl_sk->sk, NULL);

    const unsigned ec_sk_str_len = bn_size_str(state->bob_ec_sk->sk, 10);
    char ec_sk_str[ec_sk_str_len];
    bn_write_str(ec_sk_str, ec_sk_str_len, state->bob_ec_sk->sk, 10);

    GEN plain_ec_sk = strtoi(ec_sk_str);
    // compute ciphertext for signing key of tumbler
    if (cl_enc(ctx_sk_from_b, plain_ec_sk, state->bob_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }      

    ec_write_bin(serialized, RLC_EC_SIZE_COMPRESSED, state->bob_ec_pk->pk, 1);
    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {    
      ec_write_bin(serialized + (i+1) * RLC_EC_SIZE_COMPRESSED + 2 * i * BYTES_MODULUS_RSA + 2 * i * BYTES_MODULUS_RSA_2 + i * BYTES_INTERVAL_EXT_PARAM_PUB + i * BYTES_RANGE_PI_W, RLC_EC_SIZE_COMPRESSED, pk_shares[i], 1);  
      bn_write_bin(serialized + (i+2) * RLC_EC_SIZE_COMPRESSED + 2 * i * BYTES_MODULUS_RSA + 2 * i * BYTES_MODULUS_RSA_2 + i * BYTES_INTERVAL_EXT_PARAM_PUB + i * BYTES_RANGE_PI_W, BYTES_MODULUS_RSA, puzzles[i]->u);
      mpz_export(serialized + (i+2) * RLC_EC_SIZE_COMPRESSED + (2 * i + 1) * BYTES_MODULUS_RSA + 2 * i * BYTES_MODULUS_RSA_2 + i * BYTES_INTERVAL_EXT_PARAM_PUB + i * BYTES_RANGE_PI_W, &v_bytes1, 1, sizeof(unsigned char), 0, 0, puzzles[i]->v);      
      bn_write_bin(serialized + (i+2) * RLC_EC_SIZE_COMPRESSED + (2 * i + 1) * BYTES_MODULUS_RSA + (2 * i + 1) * BYTES_MODULUS_RSA_2 + i * BYTES_INTERVAL_EXT_PARAM_PUB + i * BYTES_RANGE_PI_W, BYTES_MODULUS_RSA, lhtlp_ranges->Ds[i]->u);   
      mpz_export(serialized + (i+2) * RLC_EC_SIZE_COMPRESSED + (2 * i + 2) * BYTES_MODULUS_RSA + (2 * i + 1) * BYTES_MODULUS_RSA_2 + i * BYTES_INTERVAL_EXT_PARAM_PUB + i * BYTES_RANGE_PI_W, &v_bytes2, 1, sizeof(unsigned char), 0, 0, lhtlp_ranges->Ds[i]->v);
      bn_write_bin_ext(serialized + (i+2) * RLC_EC_SIZE_COMPRESSED + (2 * i + 2) * BYTES_MODULUS_RSA + (2 * i + 2) * BYTES_MODULUS_RSA_2 + i * BYTES_INTERVAL_EXT_PARAM_PUB + i * BYTES_RANGE_PI_W, BYTES_INTERVAL_EXT_PARAM_PUB, lhtlp_ranges->Vs[i]);
      bn_write_bin(serialized + (i+2) * RLC_EC_SIZE_COMPRESSED + (2 * i + 2) * BYTES_MODULUS_RSA + (2 * i + 2) * BYTES_MODULUS_RSA_2 + (i + 1) * BYTES_INTERVAL_EXT_PARAM_PUB + i * BYTES_RANGE_PI_W, BYTES_RANGE_PI_W, lhtlp_ranges->Ws[i]);  
    }
    bn_write_bin(serialized + (BITS_STATISTIC_PARAM+2) * RLC_EC_SIZE_COMPRESSED + (2 * BITS_STATISTIC_PARAM + 2) * BYTES_MODULUS_RSA + (2 * BITS_STATISTIC_PARAM + 2) * BYTES_MODULUS_RSA_2 + (BITS_STATISTIC_PARAM + 1) * BYTES_INTERVAL_EXT_PARAM_PUB + BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W, BYTES_MODULUS_RSA_POWER, lhtlp_ranges->r);    
		
    md_map(hash, serialized, SERIALIZED_LEN);

		if (8 * RLC_MD_LEN > bn_bits(q)) {
			unsigned lenth = RLC_CEIL(bn_bits(q), 8);
			bn_read_bin(e, hash, lenth);
			bn_rsh(e, e, 8 * RLC_MD_LEN - bn_bits(q));
		} else {
			bn_read_bin(e, hash, RLC_MD_LEN);
		}
		bn_mod(e, e, q);
		
		bn_write_str(bin_from_hash, (BITS_SHA_256 + 1), e, 2);
    strncpy(bin_sub_threshold, bin_from_hash, BITS_THRESHOLD_PARAM - 1);
    binary_to_bytes(bin_sub_threshold, BITS_THRESHOLD_PARAM - 1, byte_sub_threshold, BYTES_THRESHOLD_LEN_PARAM);

    char *msg_type = "promise_init";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED) + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + BITS_THRESHOLD_PARAM * BYTES_MODULUS_RSA_POWER + ((BITS_THRESHOLD_PARAM - 1) * BYTES_ECC_ORDER) + BYTES_THRESHOLD_LEN_PARAM;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_init_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    bn_write_bin(promise_init_msg->data, RLC_BN_SIZE, state->tid);
    g1_write_bin(promise_init_msg->data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED, state->sigma_tid->sigma_1, 1);
    g1_write_bin(promise_init_msg->data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, state->sigma_tid->sigma_2, 1);
    memcpy(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE,
           GENtostr(state->bob_cl_pk->pk), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_init_msg->data + RLC_CL_CIPHERTEXT_SIZE + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE,
           GENtostr(ctx_sk_from_b->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_init_msg->data + 2 * RLC_CL_CIPHERTEXT_SIZE + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE,
           GENtostr(ctx_sk_from_b->c2), RLC_CL_CIPHERTEXT_SIZE);

    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {      
      bn_write_bin(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + (i * BYTES_MODULUS_RSA)  + (i * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE), BYTES_MODULUS_RSA, puzzles[i]->u);
      mpz_export(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((i+1) * BYTES_MODULUS_RSA)+ (i * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE), &v_bytes, 1, sizeof(unsigned char), 0, 0, puzzles[i]->v);      
    }
   
    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {      
      ec_write_bin(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM+ i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (i * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), RLC_EC_SIZE_COMPRESSED, pk_shares[i], 1);
      bn_write_bin(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_MODULUS_RSA, lhtlp_ranges->Ds[i]->u);   
      mpz_export(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), &v_bytes, 1, sizeof(unsigned char), 0, 0, lhtlp_ranges->Ds[i]->v);
      bn_write_bin_ext(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_INTERVAL_EXT_PARAM_PUB, lhtlp_ranges->Vs[i]);
      bn_write_bin(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED)  + ((i + 1) * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_RANGE_PI_W, lhtlp_ranges->Ws[i]);      
    }
    bn_write_bin(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W), BYTES_MODULUS_RSA_POWER, lhtlp_ranges->r);     
    bn_write_bin(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W), BYTES_INTERVAL_PARAM_PUB, interval_L);     
    for(int i = 0; i < BITS_THRESHOLD_PARAM - 1; i++)
    {   
      bn_write_bin(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1 ) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB +  (i + 1) * BYTES_MODULUS_RSA_POWER + (i * BYTES_ECC_ORDER), BYTES_ECC_ORDER, sk_shares[2*i + (bin_sub_threshold[i] - '0')]);                 
      bn_write_bin(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + (i + 1) * BYTES_MODULUS_RSA_POWER + ((i + 1) * BYTES_ECC_ORDER), BYTES_MODULUS_RSA_POWER, rands[2*i + (bin_sub_threshold[i] - '0')]);                 
          
    }
   
    memcpy(promise_init_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED) + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + BITS_THRESHOLD_PARAM * BYTES_MODULUS_RSA_POWER + ((BITS_THRESHOLD_PARAM - 1) * BYTES_ECC_ORDER), byte_sub_threshold, BYTES_THRESHOLD_LEN_PARAM);
    memcpy(promise_init_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_init_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_init;
    int rc = zmq_msg_init_size(&promise_init, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_init), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_init, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(N_2);
    bn_free(g_inter_prime);
    bn_free(rand_ex);
    bn_free(h_rand_ex);
    bn_free(exp);
    bn_free(N_plus_1);
    bn_free(N_plus_1_sk);
    bn_free(interval_B);
    bn_free(sk_b);
    bn_free(interval_L);
    bn_free(e);
    lhtlp_puzzle_free(puzzle);    
    cl_ciphertext_free(ctx_sk_from_b);
    message_free(promise_init_msg);
    if (serialized_message != NULL) free(serialized_message);
    lhtlp_param_free(lhtlp_param);
           
    for(int i=0; i<BITS_STATISTIC_PARAM; i++)
    {
      bn_free(sk_shares[i]);
      bn_free(lagrange_bases[i]);
      bn_free(rands[i]);
      ec_free(pk_shares[i]);
      lhtlp_puzzle_free(puzzles[i]);    
      lhtlp_puzzle_free(lhtlp_ranges->Ds[i]);
      bn_free(lhtlp_ranges->Vs[i]);
      bn_free(lhtlp_ranges->Ws[i]);
    }
    pis_lhtlp_range_free(lhtlp_ranges, BITS_STATISTIC_PARAM); 
  }

  return result_status;
}

int promise_com_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  message_t promise_zkdl_msg;

  bn_t(q);
  ec_t g_to_the_rand_for_t;

  cl_ciphertext_t ctx_sk_from_t_check;
  zk_proof_cldl_t pi_cldl;
  zk_proof_t pi_rand_for_t;

  message_null(promise_zkdl_msg);
  bn_null(q);
  ec_null(g_to_the_rand_for_t);

  cl_ciphertext_null(ctx_sk_from_t_check);
  zk_proof_cldl_null(pi_cldl);
  zk_proof_null(pi_rand_for_t);

  RLC_TRY {

    bn_new(q);
    ec_new(g_to_the_rand_for_t);

    cl_ciphertext_new(ctx_sk_from_t_check);
    zk_proof_cldl_new(pi_cldl);
    zk_proof_new(pi_rand_for_t);

    // Deserialize the data from the message.
    ec_read_bin(state->g_to_the_alpha_from_t, data, RLC_EC_SIZE_COMPRESSED);
    char ctx_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ctx_str, data + RLC_EC_SIZE_COMPRESSED, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_from_t->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + RLC_EC_SIZE_COMPRESSED + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_from_t->c2 = gp_read_str(ctx_str);

    char pi_cldl_str[RLC_CLDL_PROOF_T1_SIZE];
    memcpy(pi_cldl_str, data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_CL_CIPHERTEXT_SIZE),
           RLC_CLDL_PROOF_T1_SIZE);
    pi_cldl->t1 = gp_read_str(pi_cldl_str);
    ec_read_bin(pi_cldl->t2, data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_CL_CIPHERTEXT_SIZE) 
              + RLC_CLDL_PROOF_T1_SIZE, RLC_EC_SIZE_COMPRESSED);
    memcpy(pi_cldl_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE, RLC_CLDL_PROOF_T3_SIZE);
    pi_cldl->t3 = gp_read_str(pi_cldl_str);
    memzero(pi_cldl_str, RLC_CLDL_PROOF_T1_SIZE);
    memcpy(pi_cldl_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE, RLC_CLDL_PROOF_U1_SIZE);
    pi_cldl->u1 = gp_read_str(pi_cldl_str);
    memcpy(pi_cldl_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE, RLC_CLDL_PROOF_U2_SIZE);
    pi_cldl->u2 = gp_read_str(pi_cldl_str);

    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_check->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + (2 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_check->c2 = gp_read_str(ctx_str);
    bn_read_bin(state->com_c_from_tumbler, data + (2 * RLC_EC_SIZE_COMPRESSED) + (4 * RLC_CL_CIPHERTEXT_SIZE) 
         + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, RLC_BN_SIZE);
    ec_read_bin(state->tumbler_ec_pk2->pk, data + (2 * RLC_EC_SIZE_COMPRESSED) + (4 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);
    
    if (zk_cldl_verify(pi_cldl, state->g_to_the_alpha_from_t, state->ctx_alpha_from_t, state->tumbler_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    ec_curve_get_ord(q);
    bn_rand_mod(state->rand_for_tumbler,q);
    ec_mul_gen(g_to_the_rand_for_t,state->rand_for_tumbler);
    if (zk_dlog_prove(pi_rand_for_t, g_to_the_rand_for_t, state->rand_for_tumbler) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "promise_zkdl";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE + (3 * RLC_EC_SIZE_COMPRESSED);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_zkdl_msg, msg_type_length, msg_data_length);
    
    ec_write_bin(promise_zkdl_msg->data, RLC_EC_SIZE_COMPRESSED, g_to_the_rand_for_t, 1);
    ec_write_bin(promise_zkdl_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, pi_rand_for_t->a, 1);
    bn_write_bin(promise_zkdl_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, pi_rand_for_t->z);

    // Serialize the message.
    memcpy(promise_zkdl_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_zkdl_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_zkdl;
    int rc = zmq_msg_init_size(&promise_zkdl, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_zkdl), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_zkdl, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    ec_free(g_to_the_rand_for_t);

    cl_ciphertext_free(ctx_sk_from_t_check);
    zk_proof_cldl_free(pi_cldl);
    zk_proof_free(pi_rand_for_t);
    message_free(promise_zkdl_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int promise_decom_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  message_t promise_presig_msg;
  uint8_t h[RLC_MD_LEN];

  bn_t q;
  bn_t e;
  bn_t inv_rand;
  bn_t mul_hash;
  bn_t mul_sk;
  bn_t plain_s_hat_from_t;
  bn_t k_alpha;
  bn_t inv_k;
  ec_t g_to_alpha_k_from_t;
  ec_t g_to_alpha_2k;
  ec_t g_to_k_s_hat;
  ec_t g_to_hash;
  ec_t g_to_sk_hash;
  zk_proof_t pi_g_to_k_from_t;
  zk_proof_t pi_g_to_alpha_k_from_t;
  commit_t com_from_t;
  size_t len;
  cl_ciphertext_t ctx_hash;
  cl_ciphertext_t ctx_sk;
  cl_ciphertext_t ctx_s_hat;

  bn_null(q);
  bn_null(e);
  bn_null(inv_rand);
  bn_null(mul_hash);
  bn_null(mul_sk);
  bn_null(plain_s_hat_from_t);   
  bn_null(k_alpha);
  bn_null(inv_k);
  ec_null(g_to_alpha_k_from_t);
  ec_null(g_to_alpha_2k);
  ec_null(g_to_k_s_hat);
  ec_null(g_to_hash);
  ec_null(g_to_sk_hash);
  zk_proof_null(pi_g_to_k_from_t);
  zk_proof_null(pi_g_to_alpha_k_from_t);
  commit_null(com_from_t);  
  cl_ciphertext_null(ctx_hash);
  cl_ciphertext_null(ctx_sk);
  cl_ciphertext_null(ctx_s_hat);

  RLC_TRY {
    
    bn_new(q);
    bn_new(e);
    bn_new(inv_rand);
    bn_new(mul_hash);
    bn_new(mul_sk);
    bn_new(plain_s_hat_from_t);   
    bn_new(k_alpha);
    bn_new(inv_k);    
    ec_new(g_to_alpha_k_from_t);
    ec_new(g_to_alpha_2k);
    ec_new(g_to_k_s_hat);
    ec_new(g_to_hash);
    ec_new(g_to_sk_hash);
    zk_proof_new(pi_g_to_k_from_t);
    zk_proof_new(pi_g_to_alpha_k_from_t);
    commit_new(com_from_t);
    cl_ciphertext_new(ctx_hash);
    cl_ciphertext_new(ctx_sk);
    cl_ciphertext_new(ctx_s_hat);

    ec_read_bin(com_from_t->r, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(state->g_to_the_rand_from_t, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_g_to_k_from_t->a, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_g_to_k_from_t->z, data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);
    ec_read_bin(g_to_alpha_k_from_t, data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_g_to_alpha_k_from_t->a, data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_g_to_alpha_k_from_t->b, data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_g_to_alpha_k_from_t->z, data + (6 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE);
    
    char ct_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ct_str, data + (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), RLC_CL_CIPHERTEXT_SIZE);
    ctx_s_hat->c1 = gp_read_str(ct_str);
    memcpy(ct_str, data + (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_s_hat->c2 = gp_read_str(ct_str);

    bn_copy(com_from_t->c, state->com_c_from_tumbler);
    if (decommit(com_from_t, state->g_to_the_rand_from_t) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (zk_dlog_verify(pi_g_to_k_from_t, state->g_to_the_rand_from_t) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (zk_dhtuple_verify(pi_g_to_alpha_k_from_t, state->g_to_the_rand_from_t, state->g_to_the_alpha_from_t, g_to_alpha_k_from_t) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    // Decrypt the ciphertext.
    GEN s_hat_from_t;
    if (cl_dec(&s_hat_from_t, ctx_s_hat, state->bob_cl_sk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    bn_read_str(plain_s_hat_from_t, GENtostr(s_hat_from_t), strlen(GENtostr(s_hat_from_t)), 10);
    ec_curve_get_ord(q);
    bn_mod(plain_s_hat_from_t, plain_s_hat_from_t, q);
    ec_mul(g_to_k_s_hat, state->g_to_the_rand_from_t, plain_s_hat_from_t);

    md_map(h, tx, sizeof(tx));
    len = RLC_MD_LEN;

    if (8 * len > (size_t) bn_bits(q)) {
      len = RLC_CEIL(bn_bits(q), 8);
      bn_read_bin(e, h, len);
      bn_rsh(e, e, 8 * len - bn_bits(q));
    } else {
      bn_read_bin(e, h, len);
    }
    ec_mul_gen(g_to_hash, e);
    ec_mul(state->bob_tumbler_ec_pk->pk, state->tumbler_ec_pk2->pk, state->bob_ec_sk->sk);
    
    ec_mul(g_to_alpha_2k, g_to_alpha_k_from_t, state->rand_for_tumbler);
    ec_get_x(state->sigma_b_t_hat->r, g_to_alpha_2k);
    bn_mod(state->sigma_b_t_hat->r, state->sigma_b_t_hat->r, q);
    ec_mul(g_to_sk_hash, state->bob_tumbler_ec_pk->pk, state->sigma_b_t_hat->r);
    ec_add(g_to_sk_hash, g_to_sk_hash, g_to_hash);
    
    if (ec_cmp(g_to_k_s_hat, g_to_sk_hash) != RLC_EQ) {
      RLC_THROW(ERR_CAUGHT);
    }
    bn_mod_inv(inv_k, state->rand_for_tumbler, q);
    bn_mul(plain_s_hat_from_t, plain_s_hat_from_t, inv_k);
    bn_mod(plain_s_hat_from_t, plain_s_hat_from_t, q);
    bn_copy(state->sigma_b_t_hat->s, plain_s_hat_from_t);
   
    char *msg_type = "promise_presig";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_presig_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    bn_write_bin(promise_presig_msg->data, RLC_BN_SIZE, plain_s_hat_from_t);

    memcpy(promise_presig_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_presig_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_presig;
    int rc = zmq_msg_init_size(&promise_presig, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_presig), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_presig, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    
    bn_free(q);
    bn_free(e);
    bn_free(inv_rand);
    bn_free(mul_hash);
    bn_free(mul_sk);
    bn_free(plain_s_hat_from_t);   
    bn_free(k_alpha);    
    bn_free(inv_k);
    ec_free(g_to_alpha_k_from_t);
    ec_free(g_to_alpha_2k);
    ec_free(g_to_hash);
    ec_free(g_to_sk_hash);
    commit_free(com_from_t);
    zk_proof_free(pi_g_to_k_from_t);
    zk_proof_free(pi_g_to_alpha_k_from_t);
    cl_ciphertext_free(ctx_hash);
    cl_ciphertext_free(ctx_sk);    
    cl_ciphertext_free(ctx_s_hat);    
  }

  return result_status;
}

int promise_over_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }
  PROMISE_COMPLETED = 1;

  return RLC_OK;
}

int puzzle_share(bob_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }
  
  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  
  message_t puzzle_share_msg;
  message_null(puzzle_share_msg);

  cl_ciphertext_t ctx_alpha_times_beta;
  cl_ciphertext_t ctx_alpha_times_beta_check;
  bn_t q;
  ec_t g_to_the_alpha_times_beta;

  cl_ciphertext_null(ctx_alpha_times_beta);
  cl_ciphertext_null(ctx_alpha_times_beta_check);
  bn_null(q);
  ec_null(g_to_the_alpha_times_beta);

  RLC_TRY {
    cl_ciphertext_new(ctx_alpha_times_beta);
    cl_ciphertext_new(ctx_alpha_times_beta_check);
    bn_new(q);
    ec_new(g_to_the_alpha_times_beta);

    ec_curve_get_ord(q);

    // Randomize the promise challenge.
    GEN beta_prime = randomi(state->cl_params->bound);
    bn_read_str(state->beta, GENtostr(beta_prime), strlen(GENtostr(beta_prime)), 10);
    bn_mod(state->beta, state->beta, q);

    ec_mul(g_to_the_alpha_times_beta, state->g_to_the_alpha_from_t, state->beta);
    ec_norm(g_to_the_alpha_times_beta, g_to_the_alpha_times_beta);

    // Homomorphically randomize the challenge ciphertext.
    const unsigned beta_str_len = bn_size_str(state->beta, 10);
    char beta_str[beta_str_len];
    bn_write_str(beta_str, beta_str_len, state->beta, 10);

    GEN plain_beta = strtoi(beta_str);
    ctx_alpha_times_beta->c1 = nupow(state->ctx_alpha_from_t->c1, plain_beta, NULL);
    ctx_alpha_times_beta->c2 = nupow(state->ctx_alpha_from_t->c2, plain_beta, NULL);
    ctx_alpha_times_beta_check->c1 = nupow(state->ctx_alpha_check->c1, plain_beta, NULL);
    ctx_alpha_times_beta_check->c2 = nupow(state->ctx_alpha_check->c2, plain_beta, NULL);

    // Build and define the message.
    char *msg_type = "puzzle_share";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_EC_SIZE_COMPRESSED + (4 * RLC_CL_CIPHERTEXT_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_share_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(puzzle_share_msg->data, RLC_EC_SIZE_COMPRESSED, g_to_the_alpha_times_beta, 1);
    memcpy(puzzle_share_msg->data + RLC_EC_SIZE_COMPRESSED, GENtostr(ctx_alpha_times_beta->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(puzzle_share_msg->data + RLC_EC_SIZE_COMPRESSED + RLC_CL_CIPHERTEXT_SIZE, GENtostr(ctx_alpha_times_beta->c2), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(puzzle_share_msg->data + RLC_EC_SIZE_COMPRESSED + 2 * RLC_CL_CIPHERTEXT_SIZE, GENtostr(ctx_alpha_times_beta_check->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(puzzle_share_msg->data + RLC_EC_SIZE_COMPRESSED + 3 * RLC_CL_CIPHERTEXT_SIZE, GENtostr(ctx_alpha_times_beta_check->c2), RLC_CL_CIPHERTEXT_SIZE);
    // Serialize the message.
    memcpy(puzzle_share_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, puzzle_share_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t puzzle_share;
    int rc = zmq_msg_init_size(&puzzle_share, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&puzzle_share), serialized_message, total_msg_length);
    rc = zmq_msg_send(&puzzle_share, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    cl_ciphertext_free(ctx_alpha_times_beta);
    cl_ciphertext_free(ctx_alpha_times_beta_check);
    bn_free(q);
    ec_free(g_to_the_alpha_times_beta);
    if (puzzle_share_msg != NULL) message_free(puzzle_share_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int puzzle_share_done_handler(bob_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  PUZZLE_SHARED = 1;
  return RLC_OK;
}

int puzzle_solution_share_handler(bob_state_t state, void *socet, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  bn_t x, q, alpha, alpha_hat, alpha_inverse, beta_inverse, s2;

  bn_null(x);
  bn_null(q);
  bn_null(alpha);
  bn_null(alpha_hat);
  bn_null(alpha_inverse);
  bn_null(beta_inverse);
  bn_null(s2);

  RLC_TRY {
    bn_new(x);
    bn_new(q);
    bn_new(alpha);
    bn_new(alpha_hat);
    bn_new(alpha_inverse);
    bn_new(beta_inverse);
    bn_new(s2);
    
    // Deserialize the data from the message.
    bn_read_bin(alpha_hat, data, RLC_BN_SIZE);

    ec_curve_get_ord(q);

    // Extract the secret alpha.
    bn_gcd_ext(x, beta_inverse, NULL, state->beta, q);
    if (bn_sign(beta_inverse) == RLC_NEG) {
      bn_add(beta_inverse, beta_inverse, q);
    }

    bn_mul(alpha, alpha_hat, beta_inverse);
    bn_mod(alpha, alpha, q);

    // Complete the "almost" signature.
    bn_gcd_ext(x, alpha_inverse, NULL, alpha, q);
    if (bn_sign(alpha_inverse) == RLC_NEG) {
      bn_add(alpha_inverse, alpha_inverse, q);
    }

    bn_mul(state->sigma_b_t_hat->s, state->sigma_b_t_hat->s, alpha_inverse);
    bn_mod(state->sigma_b_t_hat->s, state->sigma_b_t_hat->s, q);
    bn_mul_dig(s2, state->sigma_b_t_hat->s, 2);
    if(bn_cmp(s2, q) == RLC_GT) {
      bn_sub(state->sigma_b_t_hat->s, q, state->sigma_b_t_hat->s);
    }

    // Verify the completed signature.
    if (cp_ecdsa_ver(state->sigma_b_t_hat->r, state->sigma_b_t_hat->s, tx, sizeof(tx), 0, state->bob_tumbler_ec_pk->pk) != 1) {
      RLC_THROW(ERR_CAUGHT);
    }
    PUZZLE_SOLVED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(x);
    bn_free(q);
    bn_free(alpha)
    bn_free(alpha_hat);
    bn_free(alpha_inverse);
    bn_free(beta_inverse);
    bn_free(s2);
  }

  return result_status;
}

int main(void)
{
  init();
  int result_status = RLC_OK;
  PROMISE_COMPLETED = 0;
  PUZZLE_SHARED = 0;
  PUZZLE_SOLVED = 0;
  TOKEN_RECEIVED = 0;

  long long start_time, stop_time, total_time;

  bob_state_t state;
  bob_state_null(state);

  void *context = zmq_ctx_new();
  if (!context) {
    fprintf(stderr, "Error: could not create a context.\n");
    exit(1);
  }

  void *socket = zmq_socket(context, ZMQ_REP);
  if (!socket) {
    fprintf(stderr, "Error: could not create a socket.\n");
    exit(1);
  }

  int rc = zmq_bind(socket, BOB_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind the socket.\n");
    exit(1);
  }

  RLC_TRY {
    bob_state_new(state);

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (read_keys_from_file_alice_bob(BOB_KEY_FILE_PREFIX,
                                      state->bob_ec_sk,
                                      state->bob_ec_pk,
                                      state->tumbler_ec_pk,
                                      state->tumbler_ps_pk,
                                      state->tumbler_cl_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!TOKEN_RECEIVED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
    }

    printf("Connecting to Tumbler...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, TUMBLER_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Alice.\n");
      exit(1);
    }

    start_time = ttimer();
    if (promise_init(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!PROMISE_COMPLETED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nPuzzle promise time: %.5f sec\n", total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
    }

    printf("Connecting to Alice...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, ALICE_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Alice.\n");
      exit(1);
    }

    if (puzzle_share(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    stop_time = ttimer();
 
    while (!PUZZLE_SHARED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    total_time = stop_time - start_time;
    printf("\nPuzzle promise and share time: %.5f sec\n", total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
    }

    socket = zmq_socket(context, ZMQ_REP);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_bind(socket, BOB_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not bind the socket.\n");
      exit(1);
    }

    while (!PUZZLE_SOLVED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }

    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nPuzzle promise and soluton time: %.5f sec\n", total_time / CLOCK_PRECISION);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bob_state_free(state);
  }
  
  rc = zmq_close(socket);
  if (rc != 0) {
    fprintf(stderr, "Error: could not close the socket.\n");
    exit(1);
  }

  rc = zmq_ctx_destroy(context);
  if (rc != 0) {
    fprintf(stderr, "Error: could not destroy the context.\n");
    exit(1);
  }

  return result_status;
}