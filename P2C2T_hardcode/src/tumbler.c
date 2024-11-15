#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "relic/relic.h"
#include "pari/pari.h"
#include "zmq.h"
#include "tumbler.h"
#include "types.h"
#include "util.h"
#include "gmp.h"

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
    case REGISTRATION_Z:
      return registration_handler;
    
    case REGISTRATION_TID:
      return registration_tid_handler;
    
    case PROMISE_INIT:
      return promise_init_handler;

    case PROMISE_ZKDL:
      return promise_zkdl_handler;

    case PROMISE_PRESIG:
      return promise_presig_handler;

    case PAYMENT_INIT:
      return payment_init_handler;

    case PAYMENT_DECOM:
      return payment_decom_handler;
    
    case PAYMENT_PRESIG:
      return payment_presig_handler;      

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(tumbler_state_t state, void *socket, zmq_msg_t message) {
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

int receive_message(tumbler_state_t state, void *socket) {
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

int registration_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  size_t v_bytes;
  long long start_time, stop_time, total_time;
  message_t registration_vtd_msg;

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
  message_null(registration_vtd_msg);
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
    
    ec_read_bin(state->alice_ec_pk->pk, data, RLC_EC_SIZE_COMPRESSED);

    bn_set_2b(interval_L, BITS_INTERVAL_PARAM_PUB);
    ec_curve_get_ord(q);
    
    polyfunc_gen(polyfunc, DEGREE_PARAM, state->tumbler_ec_sk->sk, q);  
    start_time = ttimer();
    lhtlp_param_gen(state->lhtlp_param, TIME_HARDNESS);    
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nRunning time of lhtlp_param_gen by tumbler: %.5f sec\n", total_time / CLOCK_PRECISION);
    bn_mul(N_2, state->lhtlp_param->N, state->lhtlp_param->N);
    for(int i=0; i<BITS_STATISTIC_PARAM; i++)
    {
      polyfunc_eval(sk_shares[i], polyfunc, i, q);
      ec_mul_gen(pk_shares[i], sk_shares[i]);
      bn_rand_mod(rands[i], N_2);
      if (lhtlp_puzzle_gen(puzzles[i], state->lhtlp_param, sk_shares[i], rands[i], EXTEND_S) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }    
    }
 
    if (pi_lhtlp_range_gen(lhtlp_ranges, puzzles, state->lhtlp_param, sk_shares, rands, BITS_STATISTIC_PARAM, N_2, interval_L) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }      

    ec_write_bin(serialized, RLC_EC_SIZE_COMPRESSED, state->tumbler_ec_pk->pk, 1);
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

    char *msg_type = "registration_vtd";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED) + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB 
    + BITS_THRESHOLD_PARAM * BYTES_MODULUS_RSA_POWER + ((BITS_THRESHOLD_PARAM - 1) * BYTES_ECC_ORDER) + BYTES_THRESHOLD_LEN_PARAM + RLC_EC_SIZE_COMPRESSED;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(registration_vtd_msg, msg_type_length, msg_data_length);  

    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {      
      bn_write_bin(registration_vtd_msg->data  + (i * BYTES_MODULUS_RSA)  + (i * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA, puzzles[i]->u);
      mpz_export(registration_vtd_msg->data  + ((i+1) * BYTES_MODULUS_RSA)+ (i * BYTES_MODULUS_RSA_2), &v_bytes, 1, sizeof(unsigned char), 0, 0, puzzles[i]->v);      
    }
    bn_write_bin(registration_vtd_msg->data  + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA) + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA_2), RLC_BN_SIZE, state->lhtlp_param->T);
    bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA) + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA, state->lhtlp_param->N);
    bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA, state->lhtlp_param->g);
    bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 2) * BYTES_MODULUS_RSA) + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA, state->lhtlp_param->h);
    
    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {      
      ec_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 3 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM+ i) * BYTES_MODULUS_RSA_2) 
      + (i * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), RLC_EC_SIZE_COMPRESSED, pk_shares[i], 1);
      bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 3 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_MODULUS_RSA, lhtlp_ranges->Ds[i]->u);   
      mpz_export(registration_vtd_msg->data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 4 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), &v_bytes, 1, sizeof(unsigned char), 0, 0, lhtlp_ranges->Ds[i]->v);
      bn_write_bin_ext(registration_vtd_msg->data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 4 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_INTERVAL_EXT_PARAM_PUB, lhtlp_ranges->Vs[i]);
      bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 4 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED)  + ((i + 1) * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_RANGE_PI_W, lhtlp_ranges->Ws[i]);      
    }
    bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W), BYTES_MODULUS_RSA_POWER, lhtlp_ranges->r);     
    bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W), BYTES_INTERVAL_PARAM_PUB, interval_L);     

    for(int i = 0; i < BITS_THRESHOLD_PARAM - 1; i++)
    {   
      bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4 ) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB +  (i + 1) * BYTES_MODULUS_RSA_POWER + (i * BYTES_ECC_ORDER), BYTES_ECC_ORDER, sk_shares[2*i + (bin_sub_threshold[i] - '0')]);                 
      bn_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + (i + 1) * BYTES_MODULUS_RSA_POWER + ((i + 1) * BYTES_ECC_ORDER), BYTES_MODULUS_RSA_POWER, rands[2*i + (bin_sub_threshold[i] - '0')]);          
    }

    memcpy(registration_vtd_msg->data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED) + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W)
     + BYTES_INTERVAL_PARAM_PUB + BITS_THRESHOLD_PARAM * BYTES_MODULUS_RSA_POWER + ((BITS_THRESHOLD_PARAM - 1) * BYTES_ECC_ORDER), byte_sub_threshold, BYTES_THRESHOLD_LEN_PARAM);
    ec_write_bin(registration_vtd_msg->data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED) + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB 
    + BITS_THRESHOLD_PARAM * BYTES_MODULUS_RSA_POWER + ((BITS_THRESHOLD_PARAM - 1) * BYTES_ECC_ORDER) + BYTES_THRESHOLD_LEN_PARAM, RLC_EC_SIZE_COMPRESSED, state->tumbler_ec_pk->pk, 1);

    memcpy(registration_vtd_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, registration_vtd_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t registration_vtd;
    int rc = zmq_msg_init_size(&registration_vtd, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&registration_vtd), serialized_message, total_msg_length);
    rc = zmq_msg_send(&registration_vtd, socket, ZMQ_DONTWAIT);
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
    message_free(registration_vtd_msg);
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

int registration_tid_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t registration_done_msg;
  uint8_t *serialized_message = NULL;

  pedersen_com_t com;
  pedersen_com_null(com);

  pedersen_com_zk_proof_t com_zk_proof;
  pedersen_com_zk_proof_null(com_zk_proof);

  ps_signature_t sigma_prime;
  ps_signature_null(sigma_prime);
  
  RLC_TRY {
    pedersen_com_new(com);
    pedersen_com_zk_proof_new(com_zk_proof);
    ps_signature_new(sigma_prime);

    // Deserialize the data from the message.
    g1_read_bin(com->c, data, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(com_zk_proof->c->c, data + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);
    bn_read_bin(com_zk_proof->u, data + (2 * RLC_G1_SIZE_COMPRESSED), RLC_BN_SIZE);
    bn_read_bin(com_zk_proof->v, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE);
    
    if (zk_pedersen_com_verify(com_zk_proof, state->tumbler_ps_pk->Y_1, com) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (ps_blind_sign(sigma_prime, com, state->tumbler_ps_sk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "registration_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 2 * RLC_G1_SIZE_COMPRESSED;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(registration_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    g1_write_bin(registration_done_msg->data, RLC_G1_SIZE_COMPRESSED, sigma_prime->sigma_1, 1);
    g1_write_bin(registration_done_msg->data + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, sigma_prime->sigma_2, 1);

    memcpy(registration_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, registration_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t registration_done;
    int rc = zmq_msg_init_size(&registration_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&registration_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&registration_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    pedersen_com_free(com);
    pedersen_com_zk_proof_free(com_zk_proof);
    ps_signature_free(sigma_prime);
    if (registration_done_msg != NULL) message_free(registration_done_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int promise_init_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t promise_com_msg;
  uint8_t *serialized_message = NULL;

  const unsigned SERIALIZED_LEN = (BITS_STATISTIC_PARAM+2) * RLC_EC_SIZE_COMPRESSED + (2 * BITS_STATISTIC_PARAM + 2) * BYTES_MODULUS_RSA + (2 * BITS_STATISTIC_PARAM + 2) * BYTES_MODULUS_RSA_2 + (BITS_STATISTIC_PARAM + 1) * BYTES_INTERVAL_EXT_PARAM_PUB + BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W + BYTES_MODULUS_RSA_POWER;
	size_t v_bytes1, v_bytes2;
	uint8_t serialized[SERIALIZED_LEN];
	uint8_t hash[RLC_MD_LEN];
  char bin_from_hash[BITS_SHA_256 + 1];
  int I[BITS_THRESHOLD_PARAM - 1], I_c[BITS_THRESHOLD_PARAM - 1];
  double Lag[BITS_STATISTIC_PARAM-2];

  char bin_sub_threshold[BITS_THRESHOLD_PARAM - 1];
  char bin_sub_threshold_check[BITS_THRESHOLD_PARAM -1];
  uint8_t byte_sub_threshold[BYTES_THRESHOLD_LEN_PARAM];

  bn_t q, tid, N_2, interval_L, e;  
  ec_t pk_share_lag;
  ec_t pk_share_I;
  ec_t pk_share_lag_tem;
  ec_t pk_share_check;
  zk_proof_cldl_t pi_cldl;
  ps_signature_t sigma_tid;  
  cl_ciphertext_t ctx_sk_from_t;
  cl_ciphertext_t ctx_sk_from_t_check;
  lhtlp_param_t param;
  lhtlp_puzzle_t puzzle_for_cmp;
  bn_t sk_shares[BITS_STATISTIC_PARAM];
  bn_t lagrange_bases[BITS_STATISTIC_PARAM];
  bn_t rands[BITS_STATISTIC_PARAM];
  bn_t pk_share_lag_latters[BITS_THRESHOLD_PARAM + 1];
  ec_t pk_shares[BITS_STATISTIC_PARAM];
  lhtlp_puzzle_t puzzles[BITS_STATISTIC_PARAM];
  pis_lhtlp_range_t lhtlp_ranges;

  bn_null(q);
  bn_null(tid);
  bn_null(N_2);
  bn_null(interval_L);
  bn_null(e);
  ec_null(pk_share_lag);
  ec_null(pk_share_I);  
  ec_null(pk_share_lag_tem);
  ec_null(pk_share_check);  
  zk_proof_cldl_null(pi_cldl);
  ps_signature_null(sigma_tid);
  lhtlp_param_null(param);
  lhtlp_puzzle_null(puzzle_for_cmp);
  cl_ciphertext_null(ctx_sk_from_t);
  cl_ciphertext_null(ctx_sk_from_t_check);
  pis_lhtlp_range_null(lhtlp_ranges);
  for(int i=0; i<BITS_STATISTIC_PARAM; i++)
  {
    bn_null(sk_shares[i]);
    bn_null(lagrange_bases[i]);
    bn_null(rands[i]);
    ec_null(pk_shares[i]);
    lhtlp_puzzle_null(puzzles[i]);    
  }
  for(int i=0; i<BITS_THRESHOLD_PARAM + 1; i++)
  {
    bn_null(pk_share_lag_latters[i]);
  }  

  RLC_TRY {
    bn_new(q);
    bn_new(tid);
    bn_new(N_2);
    bn_new(interval_L);
    bn_new(e);
    ec_new(pk_share_lag);
    ec_new(pk_share_I);    
    ec_new(pk_share_lag_tem);    
    ec_new(pk_share_check);   
    zk_proof_cldl_new(pi_cldl);
    ps_signature_new(sigma_tid);
    cl_ciphertext_new(ctx_sk_from_t);
    cl_ciphertext_new(ctx_sk_from_t_check);
    lhtlp_param_new(param);
    lhtlp_puzzle_new(puzzle_for_cmp);

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
    for(int i=0; i<BITS_THRESHOLD_PARAM + 1; i++)
    {
      bn_new(pk_share_lag_latters[i]);
    }  
    
    // Deserialize the data from the message.
    ec_curve_get_ord(q);

    bn_read_bin(tid, data, RLC_BN_SIZE);
    g1_read_bin(sigma_tid->sigma_1, data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(sigma_tid->sigma_2, data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);
    char ctx_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ctx_str, data + RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED, RLC_CL_CIPHERTEXT_SIZE);
    state->bob_cl_pk->pk = gp_read_str(ctx_str);
    memcpy(ctx_str, data + RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_sk_from_b->c1 = gp_read_str(ctx_str);
    memcpy(ctx_str, data + RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED + 2 * RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_sk_from_b->c2 = gp_read_str(ctx_str);    
    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {      
      bn_read_bin(puzzles[i]->u, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + (i * BYTES_MODULUS_RSA)  + (i * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE), BYTES_MODULUS_RSA);
      mpz_import(puzzles[i]->v, BYTES_MODULUS_RSA_2, 1, sizeof(unsigned char), 0, 0, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((i+1) * BYTES_MODULUS_RSA)+ (i * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE));
    }
  
    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {
      ec_read_bin(pk_shares[i], data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM+ i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (i * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), RLC_EC_SIZE_COMPRESSED);
      bn_read_bin(lhtlp_ranges->Ds[i]->u, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_MODULUS_RSA);
      mpz_import(lhtlp_ranges->Ds[i]->v, BYTES_MODULUS_RSA_2, 1, sizeof(unsigned char), 0, 0, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W));  
      
      bn_read_bin(lhtlp_ranges->Vs[i], data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W) + 1, BYTES_INTERVAL_EXT_PARAM_PUB - 1);      
      if((data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W))[0] == 0xFF) {
          bn_neg(lhtlp_ranges->Vs[i],lhtlp_ranges->Vs[i]);
      }

      bn_read_bin(lhtlp_ranges->Ws[i], data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED)  + ((i + 1) * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_RANGE_PI_W);      
    
    }
    bn_read_bin(lhtlp_ranges->r, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1 ) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W), BYTES_MODULUS_RSA_POWER);
    bn_read_bin(interval_L, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1 ) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W), BYTES_INTERVAL_PARAM_PUB);
    
    memcpy(byte_sub_threshold, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED) + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + BITS_THRESHOLD_PARAM * BYTES_MODULUS_RSA_POWER + ((BITS_THRESHOLD_PARAM - 1) * BYTES_ECC_ORDER), BYTES_THRESHOLD_LEN_PARAM);
    ec_read_bin(state->bob_ec_pk->pk, data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED) + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + BITS_THRESHOLD_PARAM * BYTES_MODULUS_RSA_POWER
       + ((BITS_THRESHOLD_PARAM - 1) * BYTES_ECC_ORDER) + BYTES_THRESHOLD_LEN_PARAM, RLC_EC_SIZE_COMPRESSED);
    bytes_to_binary(byte_sub_threshold, BYTES_THRESHOLD_LEN_PARAM, bin_sub_threshold_check, BITS_THRESHOLD_LEN_PARAM);
    
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
    
    if (binary_strings_equal(bin_sub_threshold, bin_sub_threshold_check, BITS_THRESHOLD_PARAM - 1) == RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    for(int i = 0; i < BITS_THRESHOLD_PARAM - 1; i++)
    {      
      bn_read_bin(sk_shares[2*i + (bin_sub_threshold[i] - '0')], data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1 ) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + (i + 1) * BYTES_MODULUS_RSA_POWER + (i * BYTES_ECC_ORDER), BYTES_ECC_ORDER);
      bn_read_bin(rands[2*i + (bin_sub_threshold[i] - '0')], data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 1 ) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (3 * RLC_CL_CIPHERTEXT_SIZE) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + (i + 1) * BYTES_MODULUS_RSA_POWER + ((i + 1) * BYTES_ECC_ORDER), BYTES_MODULUS_RSA_POWER);      
      I[i] = 2*i + (bin_sub_threshold[i] - '0');
      I_c[i] = 2*i + 1 - (bin_sub_threshold[i] - '0');
    }

    if (ps_verify(sigma_tid, tid, state->tumbler_ps_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    for(int i = 0; i < BITS_THRESHOLD_PARAM - 1; i++)
    { 
      Lag[2*i + (bin_sub_threshold[i] - '0')] = lagrange_basis(i, BITS_THRESHOLD_PARAM - 1, 0, I);
      Lag[2*i + 1 - (bin_sub_threshold[i] - '0')] = lagrange_basis(i, BITS_THRESHOLD_PARAM - 1, 0, I_c);

      ec_mul_gen(pk_share_lag, sk_shares[2*i + (bin_sub_threshold[i] - '0')]);
      // if(ec_cmp(pk_share_lag, pk_shares[2*i + (bin_sub_threshold[i] - '0')]) == RLC_NE) {
      //   RLC_THROW(ERR_CAUGHT);
      // }

      if (lhtlp_puzzle_gen(puzzle_for_cmp, state->lhtlp_param, sk_shares[2*i + (bin_sub_threshold[i] - '0')], rands[2*i + (bin_sub_threshold[i] - '0')], EXTEND_S)!= RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
      // The former holds.
      if (bn_cmp(puzzle_for_cmp->u, puzzles[2*i + (bin_sub_threshold[i] - '0')]->u) != RLC_EQ && mpz_cmp(puzzle_for_cmp->v, puzzles[2*i + (bin_sub_threshold[i] - '0')]->v) == 0) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    
    ec_set_infty(pk_share_I);
    for(int i = 0; i < BITS_THRESHOLD_PARAM - 1; i++)
    { 
      ec_mul_dig(pk_share_lag_tem, pk_shares[2*i + (bin_sub_threshold[i] - '0')], Lag[2*i + (bin_sub_threshold[i] - '0')]);
      ec_add(pk_share_I, pk_share_I, pk_share_lag_tem);
    }
    for(int i = 0; i < BITS_THRESHOLD_PARAM - 1; i++)
    {             
      ec_mul_dig(pk_share_lag_tem, pk_shares[2*i + 1 - (bin_sub_threshold[i] - '0')], Lag[2*i + 1 - (bin_sub_threshold[i] - '0')]);
      ec_add(pk_share_check, pk_share_I, pk_share_lag_tem);
      // hold or
      if (ec_cmp(pk_share_check, state->tumbler_ec_pk2->pk) == RLC_EQ) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    
    bn_mul(N_2, state->lhtlp_param->N, state->lhtlp_param->N);
    // hold or
    if (pi_lhtlp_range_verify(lhtlp_ranges, puzzles, state->lhtlp_param, BITS_STATISTIC_PARAM, N_2, interval_L) == RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    } 
    
    // bn_rand_mod(state->alpha, q);
    char *k_tumbler_bob_str = "63361294656317128030097722939785562721263451981116407279094929317102784511624";
    bn_read_str(state->alpha, k_tumbler_bob_str, strlen(k_tumbler_bob_str), 10);
    ec_mul_gen(state->g_to_the_alpha, state->alpha);

    const unsigned alpha_str_len = bn_size_str(state->alpha, 10);
    char alpha_str[alpha_str_len];
    bn_write_str(alpha_str, alpha_str_len, state->alpha, 10);

    GEN plain_alpha = strtoi(alpha_str);
    if (cl_enc(state->ctx_alpha, plain_alpha, state->tumbler_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    GEN alpha_check = strtoi("100");
    if (cl_enc(state->ctx_alpha_check, alpha_check, state->tumbler_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    state->ctx_alpha_check->c1 = nupow(state->ctx_alpha_check->c1, plain_alpha , NULL);
    state->ctx_alpha_check->c2 = nupow(state->ctx_alpha_check->c2, plain_alpha , NULL);
   
    if (zk_cldl_prove(pi_cldl, plain_alpha, state->ctx_alpha, state->tumbler_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    bn_rand_mod(state->rand_for_bob, q);
    ec_mul_gen(state->go_to_rand_for_bob, state->rand_for_bob);
    if (commit(state->com_for_bob,state->go_to_rand_for_bob) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "promise_com";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (3 * RLC_EC_SIZE_COMPRESSED) + (4 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE + RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_com_msg, msg_type_length, msg_data_length);
    ec_write_bin(promise_com_msg->data, RLC_EC_SIZE_COMPRESSED, state->g_to_the_alpha, 1);
    memcpy(promise_com_msg->data + RLC_EC_SIZE_COMPRESSED,
           GENtostr(state->ctx_alpha->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_com_msg->data + RLC_EC_SIZE_COMPRESSED + RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(state->ctx_alpha->c2), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_com_msg->data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_CL_CIPHERTEXT_SIZE),
           GENtostr(pi_cldl->t1), RLC_CLDL_PROOF_T1_SIZE);
    ec_write_bin(promise_com_msg->data + RLC_EC_SIZE_COMPRESSED + (2 * RLC_CL_CIPHERTEXT_SIZE) 
              + RLC_CLDL_PROOF_T1_SIZE, RLC_EC_SIZE_COMPRESSED, pi_cldl->t2, 1);
    memcpy(promise_com_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE, GENtostr(pi_cldl->t3), RLC_CLDL_PROOF_T3_SIZE);
    memcpy(promise_com_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE, GENtostr(pi_cldl->u1), RLC_CLDL_PROOF_U1_SIZE);
    memcpy(promise_com_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE, GENtostr(pi_cldl->u2), RLC_CLDL_PROOF_U2_SIZE);
    memcpy(promise_com_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, GENtostr(state->ctx_alpha_check->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_com_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, GENtostr(state->ctx_alpha_check->c2), RLC_CL_CIPHERTEXT_SIZE);
    bn_write_bin(promise_com_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (4 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE, RLC_BN_SIZE, state->com_for_bob->c);
    ec_write_bin(promise_com_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + (4 * RLC_CL_CIPHERTEXT_SIZE)
           + RLC_CLDL_PROOF_T1_SIZE + RLC_CLDL_PROOF_T3_SIZE + RLC_CLDL_PROOF_U1_SIZE + RLC_CLDL_PROOF_U2_SIZE + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, state->tumbler_ec_pk2->pk, 1);
    memcpy(promise_com_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_com_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_com;
    int rc = zmq_msg_init_size(&promise_com, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_com), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_com, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(tid); 
    bn_free(N_2);
    bn_free(interval_L);
    bn_free(e);   
    ec_free(pk_share_lag);
    ec_free(pk_share_I);     
    ec_free(pk_share_lag_tem);    
    ec_free(pk_share_check);       
    zk_proof_cldl_free(pi_cldl);
    ps_signature_free(sigma_tid);
    cl_ciphertext_free(ctx_sk_from_t);
    cl_ciphertext_free(ctx_sk_from_t_check);
    lhtlp_param_free(param);
    lhtlp_puzzle_free(puzzle_for_cmp);
    if (promise_com_msg != NULL) message_free(promise_com_msg);
    if (serialized_message != NULL) free(serialized_message);
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
    for(int i=0; i<BITS_THRESHOLD_PARAM + 1; i++)
    {
      bn_free(pk_share_lag_latters[i]);
    }      
    pis_lhtlp_range_free(lhtlp_ranges, BITS_STATISTIC_PARAM);
  }

  return result_status;
}

int promise_zkdl_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t promise_decom_msg;
  // uint8_t h[RLC_MD_LEN];
  // size_t len;

  bn_t q, e, k_alpha, inv_rand, mul_hash, mul_sk;
  zk_proof_t pi_rand_from_bob;
  zk_proof_t pi_rand_for_bob;
  zk_proof_t pi_alpha_k_for_bob;
  ec_t g_to_alpha_k;
  ec_t g_to_alpha_2k;
  cl_ciphertext_t ctx_hash;
  cl_ciphertext_t ctx_sk;
  cl_ciphertext_t ctx_s_hat;

  bn_null(q);
  bn_null(e);
  bn_null(k_alpha);
  bn_null(inv_rand);
  bn_null(mul_hash);
  bn_null(mul_sk);
  zk_proof_null(pi_rand_from_bob);
  zk_proof_null(pi_rand_for_bob);
  zk_proof_null(pi_alpha_k_for_bob);
  ec_null(g_to_alpha_k);
  ec_null(g_to_alpha_2k);
  cl_ciphertext_null(ctx_hash);
  cl_ciphertext_null(ctx_sk);
  cl_ciphertext_null(ctx_s_hat);

  RLC_TRY {
    bn_new(q);
    bn_new(e);
    bn_new(k_alpha);    
    zk_proof_new(pi_rand_from_bob);
    zk_proof_new(pi_rand_for_bob);
    zk_proof_new(pi_alpha_k_for_bob);
    ec_new(g_to_alpha_k);
    ec_new(g_to_alpha_2k);
    bn_new(inv_rand);
    bn_new(mul_hash);
    bn_new(mul_sk);
    cl_ciphertext_new(ctx_hash);
    cl_ciphertext_new(ctx_sk);
    cl_ciphertext_new(ctx_s_hat);
    
    // Deserialize the data from the message.
    ec_read_bin(state->go_to_rand_from_bob, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_rand_from_bob->a, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_rand_from_bob->z, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);
    
    if (zk_dlog_verify(pi_rand_from_bob, state->go_to_rand_from_bob) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    if (zk_dlog_prove(pi_rand_for_bob, state->go_to_rand_for_bob, state->rand_for_bob) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    ec_mul(g_to_alpha_k, state->go_to_rand_for_bob, state->alpha);
    if (zk_dhtuple_prove(pi_alpha_k_for_bob, state->go_to_rand_for_bob, state->g_to_the_alpha, g_to_alpha_k, state->alpha) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    ec_curve_get_ord(q);
    bn_mul(k_alpha, state->rand_for_bob, state->alpha);
    ec_mul(g_to_alpha_2k, state->go_to_rand_from_bob, k_alpha);

    ec_get_x(state->sigma_tb->r, g_to_alpha_2k);
    bn_mod(state->sigma_tb->r, state->sigma_tb->r, q);

    // md_map(h, tx, sizeof(tx));
    // len = RLC_MD_LEN;

    // if (8 * len > (size_t) bn_bits(q)) {
    //   len = RLC_CEIL(bn_bits(q), 8);
    //   bn_read_bin(e, h, len);
    //   bn_rsh(e, e, 8 * len - bn_bits(q));
    // } else {
    //   bn_read_bin(e, h, len);
    // }
    char *e_tumbler_bob_str = "30339892255886429080278287994388261086762710422193244105614574981527490633799";
    bn_read_str(e, e_tumbler_bob_str, strlen(e_tumbler_bob_str), 10); 

    bn_mod_inv(inv_rand, state->rand_for_bob, q);
    bn_mul(mul_hash, inv_rand, e);
    bn_mul(mul_sk, inv_rand, state->sigma_tb->r);
    bn_mul(mul_sk, mul_sk, state->tumbler_ec_sk2->sk);
   
    const unsigned hash_str_len = bn_size_str(mul_hash, 10);
    char hash_str[hash_str_len];
    bn_write_str(hash_str, hash_str_len, mul_hash, 10);

    GEN plain_hash = strtoi(hash_str);
    if (cl_enc(ctx_hash, plain_hash, state->bob_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    const unsigned sk_str_len = bn_size_str(mul_sk, 10);
    char sk_str[sk_str_len];
    bn_write_str(sk_str, sk_str_len, mul_sk, 10);

    GEN plain_sk = strtoi(sk_str);
    ctx_sk->c1 = nupow(state->ctx_sk_from_b->c1, plain_sk, NULL);
    ctx_sk->c2 = nupow(state->ctx_sk_from_b->c2, plain_sk, NULL);
    ctx_s_hat->c1 = gmul(ctx_hash->c1, ctx_sk->c1);
    ctx_s_hat->c2 = gmul(ctx_hash->c2, ctx_sk->c2);

    // Build and define the message.
    char *msg_type = "promise_decom";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE) + (2 * RLC_CL_CIPHERTEXT_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_decom_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(promise_decom_msg->data, RLC_EC_SIZE_COMPRESSED, state->com_for_bob->r, 1);
    ec_write_bin(promise_decom_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, state->go_to_rand_for_bob, 1);
    ec_write_bin(promise_decom_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, pi_rand_for_bob->a, 1);
    bn_write_bin(promise_decom_msg->data + (3 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, pi_rand_for_bob->z);
    ec_write_bin(promise_decom_msg->data + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, g_to_alpha_k, 1);
    ec_write_bin(promise_decom_msg->data + (4 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, pi_alpha_k_for_bob->a, 1);
    ec_write_bin(promise_decom_msg->data + (5 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, pi_alpha_k_for_bob->b, 1);
    bn_write_bin(promise_decom_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, pi_alpha_k_for_bob->z);
    memcpy(promise_decom_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE), GENtostr(ctx_s_hat->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(promise_decom_msg->data + (6 * RLC_EC_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE) + RLC_CL_CIPHERTEXT_SIZE, GENtostr(ctx_s_hat->c2), RLC_CL_CIPHERTEXT_SIZE);

    memcpy(promise_decom_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_decom_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_decom;
    int rc = zmq_msg_init_size(&promise_decom, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_decom), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_decom, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(e);
    bn_free(k_alpha);
    bn_free(inv_rand);
    bn_free(mul_hash);
    bn_free(mul_sk);    
    zk_proof_free(pi_rand_from_bob);
    zk_proof_free(pi_rand_for_bob);
    zk_proof_free(pi_alpha_k_for_bob);
    ec_free(g_to_alpha_k);
    ec_free(g_to_alpha_2k);
    cl_ciphertext_free(ctx_hash);
    cl_ciphertext_free(ctx_sk);
    cl_ciphertext_free(ctx_s_hat);
    if (promise_decom_msg != NULL) message_free(promise_decom_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int promise_presig_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t promise_over_msg;
  uint8_t h[RLC_MD_LEN];
  
  bn_t q, e, plain_s_hat_from_b, k_s_hat, inv_alpha;
  ec_t g_to_k_s_hat, g_to_hash, g_to_sk_hash;
  size_t len;
  cl_ciphertext_t ctx_s_hat_from_b;

  bn_null(q);
  bn_null(e);
  bn_null(plain_s_hat_from_b);
  bn_null(k_s_hat);
  bn_null(inv_alpha);
  ec_null(g_to_k_s_hat);
  ec_null(g_to_hash);
  ec_null(g_to_sk_hash);  
  cl_ciphertext_null(ctx_s_hat_from_b);

  RLC_TRY {

    bn_new(q);
    bn_new(e);
    bn_new(plain_s_hat_from_b);
    bn_new(k_s_hat);    
    bn_new(inv_alpha);    
    ec_new(g_to_k_s_hat);
    ec_new(g_to_hash);
    ec_new(g_to_sk_hash);    
    cl_ciphertext_new(ctx_s_hat_from_b);

    // Deserialize the data from the message.

    bn_read_bin(plain_s_hat_from_b, data, RLC_BN_SIZE);

    ec_curve_get_ord(q);
    bn_mul(k_s_hat, state->rand_for_bob, plain_s_hat_from_b);    
    ec_mul(g_to_k_s_hat, state->go_to_rand_from_bob, k_s_hat);

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
    ec_mul(state->tumbler_bob_ec_pk->pk, state->bob_ec_pk->pk, state->tumbler_ec_sk2->sk);
    ec_mul(g_to_sk_hash, state->tumbler_bob_ec_pk->pk, state->sigma_tb->r);
    ec_add(g_to_sk_hash, g_to_sk_hash, g_to_hash);
    // hold or
    // if (ec_cmp(g_to_k_s_hat, g_to_sk_hash) != RLC_EQ) {
    //   RLC_THROW(ERR_CAUGHT);
    // }

    bn_mod_inv(inv_alpha, state->alpha, q);
    bn_mul(plain_s_hat_from_b, plain_s_hat_from_b, inv_alpha);
    bn_mod(plain_s_hat_from_b, plain_s_hat_from_b, q);
    bn_copy(state->sigma_tb->s, plain_s_hat_from_b);

    // Build and define the message.
    char *msg_type = "promise_over";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 0;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(promise_over_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.

    memcpy(promise_over_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, promise_over_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_over;
    int rc = zmq_msg_init_size(&promise_over, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_over), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_over, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(e);
    bn_free(plain_s_hat_from_b);
    bn_free(k_s_hat);
    bn_free(inv_alpha);
    ec_free(g_to_k_s_hat);
    ec_free(g_to_hash);
    ec_free(g_to_sk_hash);    
    cl_ciphertext_free(ctx_s_hat_from_b);
    if (promise_over_msg != NULL) message_free(promise_over_msg);
    if (serialized_message != NULL) free(serialized_message);

  }

  return result_status;
}

int payment_init_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t payment_zkdl_msg;

  bn_t q, bn_check;
  cl_ciphertext_t ctx_alpha_times_beta_times_tau;
  cl_ciphertext_t ctx_alpha_times_beta_times_tau_check;  
  ec_t g_to_alpha_times_beta_times_tau;  
  ec_t g_to_gamma;

  zk_proof_t pi_k_for_a;


  bn_null(q);
  bn_null(bn_check);
  cl_ciphertext_null(ctx_alpha_times_beta_times_tau);
  cl_ciphertext_null(ctx_alpha_times_beta_times_tau_check);
  message_null(payment_zkdl_msg);
  ec_null(g_to_alpha_times_beta_times_tau);  
  ec_null(g_to_gamma);
  zk_proof_null(pi_k_for_a);
  RLC_TRY {
    bn_new(q);
    bn_new(bn_check);
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau_check);
    ec_new(g_to_alpha_times_beta_times_tau);    
    ec_new(g_to_gamma);
    zk_proof_new(pi_k_for_a);
    // Deserialize the data from the message.

    char ct_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ct_str, data, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c1 = gp_read_str(ct_str);
    memcpy(ct_str, data + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau->c2 = gp_read_str(ct_str);
    memcpy(ct_str, data + 2 * RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau_check->c1 = gp_read_str(ct_str);
    memcpy(ct_str, data + 3 * RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_alpha_times_beta_times_tau_check->c2 = gp_read_str(ct_str);
    ec_read_bin(g_to_alpha_times_beta_times_tau, data + 4 * RLC_CL_CIPHERTEXT_SIZE, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(state->com_c_from_a, data + 4 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED, RLC_BN_SIZE);
    memcpy(ct_str, data + 4 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->alice_cl_pk->pk = gp_read_str(ct_str);
    memcpy(ct_str, data + 5 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_sk_from_a->c1 = gp_read_str(ct_str);
    memcpy(ct_str, data + 6 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_sk_from_a->c2 = gp_read_str(ct_str);

    // Decrypt the ciphertext.
    GEN alpha_times_beta_times_tau, alpha_times_beta_times_tau_check;
    if (cl_dec(&alpha_times_beta_times_tau, ctx_alpha_times_beta_times_tau, state->tumbler_cl_sk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    if (cl_dec(&alpha_times_beta_times_tau_check, ctx_alpha_times_beta_times_tau_check, state->tumbler_cl_sk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    bn_read_str(state->gamma, GENtostr(alpha_times_beta_times_tau), strlen(GENtostr(alpha_times_beta_times_tau)), 10);
    bn_read_str(state->gamma_check, GENtostr(alpha_times_beta_times_tau_check), strlen(GENtostr(alpha_times_beta_times_tau_check)), 10);
    bn_read_str(bn_check, GENtostr(strtoi("100")), strlen(GENtostr(strtoi("100"))), 10);
    
    // verify the ctx_alpha_times_beta_times_tau.
    bn_mul(bn_check, bn_check, state->gamma);
    if (bn_cmp(state->gamma_check, bn_check) == RLC_EQ) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    // Verify the extracted secret.
    ec_mul_gen(g_to_gamma, state->gamma);
    if (ec_cmp(g_to_alpha_times_beta_times_tau, g_to_gamma) != RLC_EQ) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    ec_curve_get_ord(q);
    // bn_rand_mod(state->rand_for_a, q);
    char *k_tumbler_alice_str = "28052983739558424629466900342789882706463782291563821009084420100333997051927";
    bn_read_str(state->rand_for_a, k_tumbler_alice_str, strlen(k_tumbler_alice_str), 10);
    ec_mul_gen(state->g_to_rand_for_a, state->rand_for_a);
    if (zk_dlog_prove(pi_k_for_a, state->g_to_rand_for_a, state->rand_for_a) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }    

    // Build and define the message.
    char *msg_type = "payment_zkdl";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_zkdl_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(payment_zkdl_msg->data, RLC_EC_SIZE_COMPRESSED, state->g_to_rand_for_a, 1);
    ec_write_bin(payment_zkdl_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, pi_k_for_a->a, 1);
    bn_write_bin(payment_zkdl_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, pi_k_for_a->z);
    
    memcpy(payment_zkdl_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_zkdl_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_zkdl;
    int rc = zmq_msg_init_size(&payment_zkdl, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_zkdl), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_zkdl, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(bn_check);
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau);
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau_check);    
    if (payment_zkdl_msg != NULL) message_free(payment_zkdl_msg);
    if (serialized_message != NULL) free(serialized_message);
    ec_free(g_to_alpha_times_beta_times_tau);    
    ec_free(g_to_gamma);
    zk_proof_free(pi_k_for_a);
  }

  return result_status;
}

int payment_decom_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  message_t payment_ctx_msg;
  // uint8_t h[RLC_MD_LEN];

  bn_t q;
  bn_t e;
  bn_t inv_rand;
  bn_t mul_hash;
  bn_t mul_sk;
  bn_t k_gamma;
  ec_t g_to_gamma;
  ec_t g_to_gamma_k_from_t;
  ec_t g_to_gamma_2k_from_t;
  zk_proof_t pi_g_to_k_from_a;
  zk_proof_t pi_g_to_gamma_k_from_t;
  commit_t com_from_a;
  // size_t len;
  cl_ciphertext_t ctx_hash;
  cl_ciphertext_t ctx_sk;
  cl_ciphertext_t ctx_s_hat;

  bn_null(q);
  bn_null(e);
  bn_null(inv_rand);
  bn_null(mul_hash);
  bn_null(mul_sk);
  bn_null(k_gamma);
  ec_null(decom_rand_from_t);
  ec_null(g_to_gamma);
  ec_null(g_to_gamma_k_from_t);
  ec_null(g_to_gamma_2k_from_t);
  zk_proof_null(pi_g_to_k_from_a);
  zk_proof_null(pi_g_to_gamma_k_from_t);
  commit_null(com_from_a);
  cl_ciphertext_null(ctx_hash);
  cl_ciphertext_null(ctx_sk);
  cl_ciphertext_null(ctx_s_hat);

  RLC_TRY {
    
    bn_new(q);
    bn_new(e);
    bn_new(inv_rand);
    bn_new(mul_hash);
    bn_new(mul_sk);
    bn_new(k_gamma);
    ec_new(g_to_gamma);
    ec_new(g_to_gamma_k_from_t);
    ec_new(g_to_gamma_2k_from_t);
    zk_proof_new(pi_g_to_k_from_a);
    zk_proof_new(pi_g_to_gamma_k_from_t);
    commit_new(com_from_a);
    cl_ciphertext_new(ctx_hash);
    cl_ciphertext_new(ctx_sk);
    cl_ciphertext_new(ctx_s_hat);

    ec_read_bin(state->g_to_rand_from_a, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_g_to_k_from_a->a, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_g_to_k_from_a->z, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);
    ec_read_bin(com_from_a->r, data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED);
  
    bn_copy(com_from_a->c, state->com_c_from_a);
    if (decommit(com_from_a, state->g_to_rand_from_a) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (zk_dlog_verify(pi_g_to_k_from_a, state->g_to_rand_from_a) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    ec_mul_gen(g_to_gamma, state->gamma);
    ec_mul(g_to_gamma_k_from_t, state->g_to_rand_for_a, state->gamma);
    if (zk_dhtuple_prove(pi_g_to_gamma_k_from_t, state->g_to_rand_for_a, g_to_gamma, g_to_gamma_k_from_t, state->gamma) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    ec_curve_get_ord(q);
    bn_mul(k_gamma, state->rand_for_a, state->gamma);
    ec_mul(g_to_gamma_2k_from_t, state->g_to_rand_from_a, k_gamma);

    ec_get_x(state->sigma_ta->r, g_to_gamma_2k_from_t);
    bn_mod(state->sigma_ta->r, state->sigma_ta->r, q);

    // md_map(h, tx, sizeof(tx));
    // len = RLC_MD_LEN;

    // if (8 * len > (size_t) bn_bits(q)) {
    //   len = RLC_CEIL(bn_bits(q), 8);
    //   bn_read_bin(e, h, len);
    //   bn_rsh(e, e, 8 * len - bn_bits(q));
    // } else {
    //   bn_read_bin(e, h, len);
    // }
    char *e_alice_tumbler_str = "30276068045106330296389736404675343634632587935454187437739580251246250847785";
    bn_read_str(e, e_alice_tumbler_str, strlen(e_alice_tumbler_str), 10); 

    bn_mod_inv(inv_rand, state->rand_for_a, q);
    bn_mul(mul_hash, inv_rand, e);
    bn_mul(mul_sk, inv_rand, state->sigma_ta->r);
    bn_mul(mul_sk, mul_sk, state->tumbler_ec_sk->sk);
   
    const unsigned hash_str_len = bn_size_str(mul_hash, 10);
    char hash_str[hash_str_len];
    bn_write_str(hash_str, hash_str_len, mul_hash, 10);

    GEN plain_hash = strtoi(hash_str);
    if (cl_enc(ctx_hash, plain_hash, state->alice_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    const unsigned sk_str_len = bn_size_str(mul_sk, 10);
    char sk_str[sk_str_len];
    bn_write_str(sk_str, sk_str_len, mul_sk, 10);

    GEN plain_sk = strtoi(sk_str);
    ctx_sk->c1 = nupow(state->ctx_sk_from_a->c1, plain_sk, NULL);
    ctx_sk->c2 = nupow(state->ctx_sk_from_a->c2, plain_sk, NULL);
    ctx_s_hat->c1 = gmul(ctx_hash->c1, ctx_sk->c1);
    ctx_s_hat->c2 = gmul(ctx_hash->c2, ctx_sk->c2);
    
    char *msg_type = "payment_ctx";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_CL_CIPHERTEXT_SIZE)  + (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_ctx_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    memcpy(payment_ctx_msg->data, GENtostr(ctx_s_hat->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(payment_ctx_msg->data + RLC_CL_CIPHERTEXT_SIZE, GENtostr(ctx_s_hat->c2), RLC_CL_CIPHERTEXT_SIZE);
    ec_write_bin(payment_ctx_msg->data + (2 * RLC_CL_CIPHERTEXT_SIZE), RLC_EC_SIZE_COMPRESSED, g_to_gamma_k_from_t, 1);
    ec_write_bin(payment_ctx_msg->data + (2 * RLC_CL_CIPHERTEXT_SIZE) + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, pi_g_to_gamma_k_from_t->a, 1);
    ec_write_bin(payment_ctx_msg->data + (2 * RLC_CL_CIPHERTEXT_SIZE) + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED, pi_g_to_gamma_k_from_t->b, 1);
    bn_write_bin(payment_ctx_msg->data + (2 * RLC_CL_CIPHERTEXT_SIZE) + (3 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, pi_g_to_gamma_k_from_t->z);
    
    // Serialize the message.
    memcpy(payment_ctx_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_ctx_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_ctx;
    int rc = zmq_msg_init_size(&payment_ctx, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_ctx), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_ctx, socket, ZMQ_DONTWAIT);
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
    bn_free(k_gamma);
    ec_free(g_to_gamma);
    ec_free(g_to_gamma_k_from_t);
    ec_free(g_to_gamma_2k_from_t);
    commit_free(com_from_a);
    zk_proof_free(pi_g_to_k_from_a);
    zk_proof_free(pi_g_to_gamma_k_from_t);
    cl_ciphertext_free(ctx_hash);
    cl_ciphertext_free(ctx_sk);    
    cl_ciphertext_free(ctx_s_hat);    
  }
  return result_status;
}

int payment_presig_handler(tumbler_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  message_t payment_sig_msg;
  uint8_t *serialized_message = NULL;

  bn_t q;
  bn_t x;
  bn_t inv_gamma;
  bn_t k_mul_s_from_t;
  bn_t s2;

  bn_null(q);
  bn_null(x);
  bn_null(inv_gamma);
  bn_null(k_mul_s_from_t);
  bn_null(s2);

  RLC_TRY {
    
    bn_new(q);
    bn_new(x);
    bn_new(inv_gamma);
    bn_new(k_mul_s_from_t);
    bn_new(s2);

    bn_read_bin(state->sigma_ta->s, data, RLC_BN_SIZE);    

    ec_curve_get_ord(q);
    bn_gcd_ext(x, inv_gamma, NULL, state->gamma, q);
    if (bn_sign(inv_gamma) == RLC_NEG) {
      bn_add(inv_gamma, inv_gamma, q);
    }
    bn_mul(state->sigma_ta->s, state->sigma_ta->s, inv_gamma);
    // printf("wit of 2AS in tumbler.c:\n");
    // bn_print(inv_gamma);
    bn_mod(state->sigma_ta->s, state->sigma_ta->s, q);

    bn_mul_dig(s2, state->sigma_ta->s, 2);
    if(bn_cmp(s2, q) == RLC_GT) {
      bn_sub(state->sigma_ta->s, q, state->sigma_ta->s);
    }
    // Verify the completed signature.
    ec_mul(state->tumbler_alice_ec_pk->pk, state->alice_ec_pk->pk, state->tumbler_ec_sk->sk);
    char *e_alice_tumbler_str = "30276068045106330296389736404675343634632587935454187437739580251246250847785";
    if (cp_ecdsa_ver_for_2as(state->sigma_ta->r, state->sigma_ta->s, e_alice_tumbler_str, state->tumbler_alice_ec_pk->pk) != 1) {
      RLC_THROW(ERR_CAUGHT);
    }
    printf("r of 2AS in tumbler.c:\n");
    bn_print(state->sigma_ta->r);
    printf("s of 2AS in tumbler.c:\n");
    bn_print(state->sigma_ta->s);

    // Build and define the message.
    char *msg_type = "payment_sig";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_sig_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    bn_write_bin(payment_sig_msg->data, RLC_BN_SIZE, state->sigma_ta->s);

    memcpy(payment_sig_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_sig_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_sig;
    int rc = zmq_msg_init_size(&payment_sig, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_sig), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_sig, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }    
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {    
    bn_free(q);
    bn_free(x);
    bn_free(inv_gamma);
    bn_free(k_mul_s_from_t);
    bn_free(s2);
  }
  return result_status;
}

int main(void)
{
  init();
  int result_status = RLC_OK;
  bn_t q;
  bn_t r, s;
  bn_null(q);
  bn_null(r);
  bn_null(s);

  tumbler_state_t state;
  tumbler_state_null(state);
  
  // Bind the socket to talk to clients.
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

  int rc = zmq_bind(socket, TUMBLER_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind the socket.\n");
    exit(1);
  }

  RLC_TRY {
    tumbler_state_new(state);
    bn_new(q);
    bn_new(r);
		bn_new(s);
    ec_curve_get_ord(q);
    if (generate_cl_params(state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    if (read_keys_from_file_tumbler(state->tumbler_ec_sk,
                                    state->tumbler_ec_pk,
                                    state->tumbler_ps_sk,
                                    state->tumbler_ps_pk,
                                    state->tumbler_cl_sk,
                                    state->tumbler_cl_pk,
                                    state->alice_ec_pk,
                                    state->bob_ec_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    bn_read_str(state->tumbler_ec_sk->sk, "6921E870D2D2915474F6C34DD68260436769C2EDACDC0FC816DF7E860128C999", strlen("6921E870D2D2915474F6C34DD68260436769C2EDACDC0FC816DF7E860128C999"), 16);
    printf("**sk_h1:\n");
    bn_print(state->tumbler_ec_sk->sk); 
    ec_mul_gen(state->tumbler_ec_pk->pk, state->tumbler_ec_sk->sk);
    
    bn_read_str(state->tumbler_ec_sk2->sk, "DBC8B40E03E646C69814D43D87D8632AC79031B31793DB58073F2249C11698CF", strlen("DBC8B40E03E646C69814D43D87D8632AC79031B31793DB58073F2249C11698CF"), 16);
    printf("**sk_h2:\n");
    bn_print(state->tumbler_ec_sk2->sk); 
    ec_mul_gen(state->tumbler_ec_pk2->pk, state->tumbler_ec_sk2->sk);

// Tumbler is always on-line
    while (1) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    tumbler_state_free(state);
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
  bn_free(q);
  bn_free(r);
  bn_free(s);
  clean();

  return result_status;
}