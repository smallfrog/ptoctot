#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "relic/relic.h"
#include "pari/pari.h"
#include "zmq.h"
#include "alice.h"
#include "types.h"
#include "util.h"

unsigned REGISTRATION_COMPLETED;
unsigned PUZZLE_SHARED;
unsigned PUZZLE_SOLVED;

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
    case REGISTRATION_VTD:
      return registration_vtd_handler;

    case REGISTRATION_DONE:
      return registration_done_handler;      
    
    case PUZZLE_SHARE:
      return puzzle_share_handler;

    case PAYMENT_ZKDL:
      return payment_zkdl_handler;

    case PAYMENT_CTX:
      return payment_ctx_handler;

    case PAYMENT_SIG:
      return payment_sig_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(alice_state_t state, void *socket, zmq_msg_t message) {
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

int receive_message(alice_state_t state, void *socket) {
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

int registration(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t registration_msg;

  RLC_TRY {   

    // Build and define the message.
    char *msg_type = "registration_z";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 0;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(registration_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    memcpy(registration_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, registration_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t registration_z;
    int rc = zmq_msg_init_size(&registration_z, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&registration_z), serialized_message, total_msg_length);
    rc = zmq_msg_send(&registration_z, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (registration_msg != NULL) message_free(registration_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int registration_vtd_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }
  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  
  message_t registration_tid_msg;
  message_null(registration_tid_msg);
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
  pedersen_com_zk_proof_t com_zk_proof;
  pedersen_com_zk_proof_null(com_zk_proof);

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
    pedersen_com_zk_proof_new(com_zk_proof);
    ec_curve_get_ord(q);
    // Deserialize the data from the message.
    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {      
      bn_read_bin(puzzles[i]->u, data  + (i * BYTES_MODULUS_RSA)  + (i * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA);
      // bn_read_bin(puzzles[i]->v, data  + ((i + 1) * BYTES_MODULUS_RSA)  + (i * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA_2);
      mpz_import(puzzles[i]->v, BYTES_MODULUS_RSA_2, 1, sizeof(unsigned char), 0, 0, data  + ((i+1) * BYTES_MODULUS_RSA)+ (i * BYTES_MODULUS_RSA_2));
    }
    bn_read_bin(state->lhtlp_param->T, data  + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA) + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA_2), RLC_BN_SIZE);
    bn_read_bin(state->lhtlp_param->N, data + RLC_BN_SIZE + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA) + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA);
    bn_read_bin(state->lhtlp_param->g, data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 1) * BYTES_MODULUS_RSA) + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA);
    bn_read_bin(state->lhtlp_param->h, data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 2) * BYTES_MODULUS_RSA) + (BITS_STATISTIC_PARAM * BYTES_MODULUS_RSA_2), BYTES_MODULUS_RSA);
    for(int i = 0; i <BITS_STATISTIC_PARAM; i++)
    {
      ec_read_bin(pk_shares[i], data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 3 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM+ i) * BYTES_MODULUS_RSA_2) 
      + (i * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), RLC_EC_SIZE_COMPRESSED);
      bn_read_bin(lhtlp_ranges->Ds[i]->u, data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 3 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_MODULUS_RSA);
      mpz_import(lhtlp_ranges->Ds[i]->v, BYTES_MODULUS_RSA_2, 1, sizeof(unsigned char), 0, 0, data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 4 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W));      
      bn_read_bin(lhtlp_ranges->Vs[i], data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 4 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W) + 1, BYTES_INTERVAL_EXT_PARAM_PUB - 1);      
      if((data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 4 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED) + (i * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W))[0] == 0xFF) {
          bn_neg(lhtlp_ranges->Vs[i],lhtlp_ranges->Vs[i]);
      }

      bn_read_bin(lhtlp_ranges->Ws[i], data + RLC_BN_SIZE + ((BITS_STATISTIC_PARAM + 4 + i) * BYTES_MODULUS_RSA) + ((BITS_STATISTIC_PARAM + 1 + i) * BYTES_MODULUS_RSA_2) 
      + ((i + 1) * RLC_EC_SIZE_COMPRESSED)  + ((i + 1) * BYTES_INTERVAL_EXT_PARAM_PUB) + (i * BYTES_RANGE_PI_W), BYTES_RANGE_PI_W);      
    
    }
    bn_read_bin(lhtlp_ranges->r, data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W), BYTES_MODULUS_RSA_POWER);
    bn_read_bin(interval_L, data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
    + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W), BYTES_INTERVAL_PARAM_PUB);
    
    memcpy(byte_sub_threshold, data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED) + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W)
     + BYTES_INTERVAL_PARAM_PUB + BITS_THRESHOLD_PARAM * BYTES_MODULUS_RSA_POWER + ((BITS_THRESHOLD_PARAM - 1) * BYTES_ECC_ORDER), BYTES_THRESHOLD_LEN_PARAM);
    
    bytes_to_binary(byte_sub_threshold, BYTES_THRESHOLD_LEN_PARAM, bin_sub_threshold_check, BITS_THRESHOLD_LEN_PARAM);
    
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
    // hold or
    if (binary_strings_equal(bin_sub_threshold, bin_sub_threshold_check, BITS_THRESHOLD_PARAM - 1) == RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    for(int i = 0; i < BITS_THRESHOLD_PARAM - 1; i++)
    {      
      bn_read_bin(sk_shares[2*i + (bin_sub_threshold[i] - '0')], data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4 ) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + (i + 1) * BYTES_MODULUS_RSA_POWER + (i * BYTES_ECC_ORDER), BYTES_ECC_ORDER);
      bn_read_bin(rands[2*i + (bin_sub_threshold[i] - '0')], data + RLC_BN_SIZE + ((2 * BITS_STATISTIC_PARAM + 4) * BYTES_MODULUS_RSA) + ((2 * BITS_STATISTIC_PARAM ) * BYTES_MODULUS_RSA_2) 
      + (BITS_STATISTIC_PARAM * RLC_EC_SIZE_COMPRESSED)  + (BITS_STATISTIC_PARAM * BYTES_INTERVAL_EXT_PARAM_PUB) + (BITS_STATISTIC_PARAM * BYTES_RANGE_PI_W) + BYTES_INTERVAL_PARAM_PUB + (i + 1) * BYTES_MODULUS_RSA_POWER + ((i + 1) * BYTES_ECC_ORDER), BYTES_MODULUS_RSA_POWER);      
      I[i] = 2*i + (bin_sub_threshold[i] - '0');
      I_c[i] = 2*i + 1 - (bin_sub_threshold[i] - '0');
    }

    for(int i = 0; i < BITS_THRESHOLD_PARAM - 1; i++)
    { 
      Lag[2*i + (bin_sub_threshold[i] - '0')] = lagrange_basis(i, BITS_THRESHOLD_PARAM - 1, 0, I);
      Lag[2*i + 1 - (bin_sub_threshold[i] - '0')] = lagrange_basis(i, BITS_THRESHOLD_PARAM - 1, 0, I_c);

      ec_mul_gen(pk_share_lag, sk_shares[2*i + (bin_sub_threshold[i] - '0')]);
      // not all hold
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
      if (ec_cmp(pk_share_check, state->tumbler_ec_pk->pk) == RLC_EQ) {
        RLC_THROW(ERR_CAUGHT);
      }
    }

    bn_mul(N_2, state->lhtlp_param->N, state->lhtlp_param->N);
    // hold or
    if (pi_lhtlp_range_verify(lhtlp_ranges, puzzles, state->lhtlp_param, BITS_STATISTIC_PARAM, N_2, interval_L) == RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    } 
    
    bn_rand_mod(state->tid, q);
    if (pedersen_commit(state->pcom, state->pdecom, state->tumbler_ps_pk->Y_1, state->tid) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (zk_pedersen_com_prove(com_zk_proof, state->tumbler_ps_pk->Y_1, state->pcom, state->pdecom) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "registration_tid";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (2 * RLC_G1_SIZE_COMPRESSED) + (2 * RLC_BN_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(registration_tid_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    g1_write_bin(registration_tid_msg->data, RLC_G1_SIZE_COMPRESSED, state->pcom->c, 1);
    g1_write_bin(registration_tid_msg->data + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, com_zk_proof->c->c, 1);
    bn_write_bin(registration_tid_msg->data + (2 * RLC_G1_SIZE_COMPRESSED), RLC_BN_SIZE, com_zk_proof->u);
    bn_write_bin(registration_tid_msg->data + (2 * RLC_G1_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_BN_SIZE, com_zk_proof->v);
    
    memcpy(registration_tid_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, registration_tid_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t registration_tid;
    int rc = zmq_msg_init_size(&registration_tid, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&registration_tid), serialized_message, total_msg_length);
    rc = zmq_msg_send(&registration_tid, socket, ZMQ_DONTWAIT);
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
    cl_ciphertext_free(ctx_sk_from_t);
    cl_ciphertext_free(ctx_sk_from_t_check);
    lhtlp_param_free(param);
    lhtlp_puzzle_free(puzzle_for_cmp);
    pedersen_com_zk_proof_free(com_zk_proof);
    if (registration_tid_msg != NULL) message_free(registration_tid_msg);
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

int registration_done_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  bn_t q, t;
  bn_null(q);
  bn_null(t);

  RLC_TRY {
    bn_new(q);
    bn_new(t);

    // Deserialize the data from the message.
    g1_read_bin(state->sigma_tid->sigma_1, data, RLC_G1_SIZE_COMPRESSED);
    g1_read_bin(state->sigma_tid->sigma_2, data + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED);

    if (ps_unblind(state->sigma_tid, state->pdecom) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (ps_verify(state->sigma_tid, state->tid, state->tumbler_ps_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    
    g1_get_ord(q);
    bn_rand_mod(t, q);

    g1_mul(state->sigma_tid->sigma_1, state->sigma_tid->sigma_1, t);
    g1_mul(state->sigma_tid->sigma_2, state->sigma_tid->sigma_2, t);
    REGISTRATION_COMPLETED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_new(q);
    bn_new(t);
  }

  return result_status;
}

int token_share(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;

  message_t token_share_msg;
  message_null(token_share_msg);

  RLC_TRY {
    // Build and define the message.
    char *msg_type = "token_share";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 2 * RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED + 3 * BYTES_MODULUS_RSA;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(token_share_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(token_share_msg->data, RLC_BN_SIZE, state->tid);
    g1_write_bin(token_share_msg->data + RLC_BN_SIZE, RLC_G1_SIZE_COMPRESSED, state->sigma_tid->sigma_1, 1);
    g1_write_bin(token_share_msg->data + RLC_BN_SIZE + RLC_G1_SIZE_COMPRESSED, RLC_G1_SIZE_COMPRESSED, state->sigma_tid->sigma_2, 1);
    bn_write_bin(token_share_msg->data  + RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED, RLC_BN_SIZE, state->lhtlp_param->T);
    bn_write_bin(token_share_msg->data + 2 * RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED, BYTES_MODULUS_RSA, state->lhtlp_param->N);
    bn_write_bin(token_share_msg->data + 2 * RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED + BYTES_MODULUS_RSA, BYTES_MODULUS_RSA, state->lhtlp_param->g);
    bn_write_bin(token_share_msg->data + 2 * RLC_BN_SIZE + 2 * RLC_G1_SIZE_COMPRESSED + 2 * BYTES_MODULUS_RSA, BYTES_MODULUS_RSA, state->lhtlp_param->h);
    // Serialize the message.
    memcpy(token_share_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, token_share_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t token_share;
    int rc = zmq_msg_init_size(&token_share, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&token_share), serialized_message, total_msg_length);
    rc = zmq_msg_send(&token_share, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (token_share_msg != NULL) message_free(token_share_msg);
    if (serialized_message != NULL) free(serialized_message);
  }
 
  return result_status;
}

int puzzle_share_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t puzzle_share_done_msg;

  RLC_TRY {
    // Deserialize the data from the message.
    ec_read_bin(state->g_to_the_alpha_times_beta, data, RLC_EC_SIZE_COMPRESSED);
    
    char ctx_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ctx_str, data + RLC_EC_SIZE_COMPRESSED, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_times_beta->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + RLC_EC_SIZE_COMPRESSED + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_times_beta->c2 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + RLC_EC_SIZE_COMPRESSED + 2 * RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_times_beta_check->c1 = gp_read_str(ctx_str);
    memzero(ctx_str, RLC_CL_CIPHERTEXT_SIZE);
    memcpy(ctx_str, data + RLC_EC_SIZE_COMPRESSED + 3 * RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    state->ctx_alpha_times_beta_check->c2 = gp_read_str(ctx_str);

    // Build and define the message.
    char *msg_type = "puzzle_share_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 0;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_share_done_msg, msg_type_length, msg_data_length);
    
    // Serialize the message.
    memcpy(puzzle_share_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, puzzle_share_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t promise_share_done;
    int rc = zmq_msg_init_size(&promise_share_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&promise_share_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&promise_share_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    PUZZLE_SHARED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (puzzle_share_done_msg != NULL) message_free(puzzle_share_done_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_init(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;

  message_t payment_init_msg;
  message_null(payment_init_msg);
  
  commit_t com;
  // NOTE: Commented parts are for doubly randomized version.
  cl_ciphertext_t ctx_alpha_times_beta_times_tau;
  cl_ciphertext_t ctx_alpha_times_beta_times_tau_check;
  cl_ciphertext_t ctx_sk_from_a;
  // cl_ciphertext_t ctx_sk_from_a_check;
  // cl_ciphertext_t ctx_alpha_check;
  bn_t q;
  
  // ec_t g_to_the_alpha_times_beta_times_tau;

  commit_null(com);
  cl_ciphertext_null(ctx_alpha_times_beta_times_tau);
  cl_ciphertext_null(ctx_alpha_times_beta_times_tau_check);
  cl_ciphertext_null(ctx_sk_from_a);
  // cl_ciphertext_null(ctx_sk_from_a_check);
  // cl_ciphertext_null(ctx_alpha_check);
  bn_null(q);
  
  // ec_null(g_to_the_alpha_times_beta_times_tau);

  RLC_TRY {

    commit_new(com);
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau);
    cl_ciphertext_new(ctx_alpha_times_beta_times_tau_check);
    cl_ciphertext_new(ctx_sk_from_a);
    // cl_ciphertext_new(ctx_sk_from_a_check);
    // cl_ciphertext_new(ctx_alpha_check);
    bn_new(q);
    
    // ec_new(g_to_the_alpha_times_beta_times_tau);
    ec_curve_get_ord(q);

    // Homomorphically randomize the challenge ciphertext.
    GEN tau_prime = randomi(state->cl_params->bound);
    bn_read_str(state->tau, GENtostr(tau_prime), strlen(GENtostr(tau_prime)), 10);
    bn_mod(state->tau, state->tau, q);
    // ec_mul(state->g_to_the_alpha_times_beta_times_tau, state->g_to_the_alpha_times_beta, state->tau);

    const unsigned tau_str_len = bn_size_str(state->tau, 10);
    char tau_str[tau_str_len];
    bn_write_str(tau_str, tau_str_len, state->tau, 10);

    GEN plain_tau = strtoi(tau_str);
    ctx_alpha_times_beta_times_tau->c1 = nupow(state->ctx_alpha_times_beta->c1, plain_tau, NULL);
    ctx_alpha_times_beta_times_tau->c2 = nupow(state->ctx_alpha_times_beta->c2, plain_tau, NULL);
    ctx_alpha_times_beta_times_tau_check->c1 = nupow(state->ctx_alpha_times_beta_check->c1, plain_tau, NULL);
    ctx_alpha_times_beta_times_tau_check->c2 = nupow(state->ctx_alpha_times_beta_check->c2, plain_tau, NULL);

    // Randomize the promise challenge.
    ec_mul(state->g_to_the_alpha_times_beta_times_tau,state->g_to_the_alpha_times_beta,state->tau);
    ec_norm(state->g_to_the_alpha_times_beta_times_tau,state->g_to_the_alpha_times_beta_times_tau);
    
    bn_rand_mod(state->rand_for_t, q);
    ec_mul_gen(state->g_to_rand_for_t, state->rand_for_t);

    if (commit(com, state->g_to_rand_for_t) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    ec_copy(state->com_r_from_a, com->r);
    // Compute CL encryption secret/public key pair for the alice.
		state->alice_cl_sk->sk = randomi(state->cl_params->bound);
		state->alice_cl_pk->pk = nupow(state->cl_params->g_q, state->alice_cl_sk->sk, NULL);

    const unsigned ec_sk_str_len = bn_size_str(state->alice_ec_sk->sk, 10);
    char ec_sk_str[ec_sk_str_len];
    bn_write_str(ec_sk_str, ec_sk_str_len, state->alice_ec_sk->sk, 10);

    GEN plain_ec_sk = strtoi(ec_sk_str);
    // compute ciphertext for signing key of tumbler
    if (cl_enc(ctx_sk_from_a, plain_ec_sk, state->alice_cl_pk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // ctx_sk_from_a_check->c1 = nupow(ctx_alpha_check->c1, plain_ec_sk , NULL);
    // ctx_sk_from_a_check->c2 = nupow(ctx_alpha_check->c2, plain_ec_sk , NULL);

    // Build and define the message.
    char *msg_type = "payment_init";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length =(9 * RLC_CL_CIPHERTEXT_SIZE) + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_init_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    memcpy(payment_init_msg->data,
           GENtostr(ctx_alpha_times_beta_times_tau->c1), RLC_CL_CIPHERTEXT_SIZE); //ctx_alpha_times_beta_times_tau->c1
    memcpy(payment_init_msg->data + RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(ctx_alpha_times_beta_times_tau->c2), RLC_CL_CIPHERTEXT_SIZE); //ctx_alpha_times_beta_times_tau->c2
    memcpy(payment_init_msg->data + 2 * RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(ctx_alpha_times_beta_times_tau_check->c1), RLC_CL_CIPHERTEXT_SIZE); 
    memcpy(payment_init_msg->data + 3 * RLC_CL_CIPHERTEXT_SIZE,
           GENtostr(ctx_alpha_times_beta_times_tau_check->c2), RLC_CL_CIPHERTEXT_SIZE); 
    ec_write_bin(payment_init_msg->data + 4 * RLC_CL_CIPHERTEXT_SIZE, RLC_EC_SIZE_COMPRESSED, state->g_to_the_alpha_times_beta_times_tau, 1);
    bn_write_bin(payment_init_msg->data + 4 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED, RLC_BN_SIZE, com->c);
    memcpy(payment_init_msg->data + 4 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
           GENtostr(state->alice_cl_pk->pk), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(payment_init_msg->data + 5 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
           GENtostr(ctx_sk_from_a->c1), RLC_CL_CIPHERTEXT_SIZE);
    memcpy(payment_init_msg->data + 6 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
           GENtostr(ctx_sk_from_a->c2), RLC_CL_CIPHERTEXT_SIZE);      
    // memcpy(payment_init_msg->data + 7 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
    //        GENtostr(ctx_sk_from_a_check->c1), RLC_CL_CIPHERTEXT_SIZE);  
    // memcpy(payment_init_msg->data + 8 * RLC_CL_CIPHERTEXT_SIZE + RLC_EC_SIZE_COMPRESSED + RLC_BN_SIZE,
    //        GENtostr(ctx_sk_from_a_check->c2), RLC_CL_CIPHERTEXT_SIZE);                                        
    // Serialize the message.
    memcpy(payment_init_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_init_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_init;
    int rc = zmq_msg_init_size(&payment_init, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_init), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_init, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    commit_free(com);
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau);
    cl_ciphertext_free(ctx_alpha_times_beta_times_tau_check);
    cl_ciphertext_free(ctx_sk_from_a);
    bn_free(q);    
    if (payment_init_msg != NULL) message_free(payment_init_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int payment_zkdl_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;
  message_t payment_decom_msg;
  
  zk_proof_t pi_g_to_rand_from_t;
  zk_proof_t pi_g_to_rand_for_t;
  cl_ciphertext_t ctx_cl_sk_from_t;

  bn_t q, x, sigma_s_inverse, gamma, tau_inverse; //tau_inverse  

  zk_proof_null(pi_g_to_rand_from_t);
  zk_proof_null(pi_g_to_rand_for_t);
  cl_ciphertext_null(ctx_cl_sk_from_t);

  bn_null(q);
  bn_null(x);
  bn_null(sigma_s_inverse);
  bn_null(gamma);
  bn_null(tau_inverse);

  RLC_TRY {

    zk_proof_new(pi_g_to_rand_from_t);
    zk_proof_new(pi_g_to_rand_for_t);
    cl_ciphertext_new(ctx_cl_sk_from_t);    

    bn_new(q);
    bn_new(x);
    bn_new(sigma_s_inverse);
    bn_new(gamma);
    bn_new(tau_inverse);    
    ec_curve_get_ord(q);

    // Deserialize the data from the message.
    ec_read_bin(state->g_to_rand_from_t, data, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_g_to_rand_from_t->a, data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_g_to_rand_from_t->z, data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);      

    if (zk_dlog_verify(pi_g_to_rand_from_t, state->g_to_rand_from_t) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (zk_dlog_prove(pi_g_to_rand_for_t, state->g_to_rand_for_t, state->rand_for_t) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    char *msg_type = "payment_decom";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = (3 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_decom_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    ec_write_bin(payment_decom_msg->data, RLC_EC_SIZE_COMPRESSED, state->g_to_rand_for_t, 1);
    ec_write_bin(payment_decom_msg->data + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED, pi_g_to_rand_for_t->a, 1);
    bn_write_bin(payment_decom_msg->data + (2 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE, pi_g_to_rand_for_t->z);
    ec_write_bin(payment_decom_msg->data + (2 * RLC_EC_SIZE_COMPRESSED) + RLC_BN_SIZE, RLC_EC_SIZE_COMPRESSED, state->com_r_from_a, 1);
    
    memcpy(payment_decom_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_decom_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_decom;
    int rc = zmq_msg_init_size(&payment_decom, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_decom), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_decom, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    
    zk_proof_free(pi_g_to_rand_from_t);
    zk_proof_free(pi_g_to_rand_for_t);
    cl_ciphertext_free(ctx_cl_sk_from_t);    
    bn_free(q);
    bn_free(x);
    bn_free(sigma_s_inverse);
    bn_free(tau_inverse);     
  }
 
  return result_status;
}

int payment_ctx_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  uint8_t *serialized_message = NULL;
  message_t payment_presig_msg;
  uint8_t h[RLC_MD_LEN];
  
  bn_t q, e, plain_s_hat_from_t, r_sigma_at, inv_k;
  ec_t g_to_k_s_hat, g_to_hash, g_to_sk_hash, g_to_gamma_2k, g_to_k_gamma;
  size_t len;
  cl_ciphertext_t ctx_s_hat_from_t;
  zk_proof_t pi_2dl;

  bn_null(q);
  bn_null(e);
  bn_null(plain_s_hat_from_t);
  bn_null(r_sigma_at);
  bn_null(inv_k);
  ec_null(g_to_k_s_hat);
  ec_null(g_to_hash);
  ec_null(g_to_sk_hash);
  ec_null(g_to_gamma_2k);
  ec_null(g_to_k_gamma);
  cl_ciphertext_null(ctx_s_hat_from_t);
  zk_proof_null(pi_2dl);

  RLC_TRY {

    bn_new(q);
    bn_new(e);
    bn_new(plain_s_hat_from_t);
    bn_new(r_sigma_at);    
    bn_new(inv_k);    
    ec_new(g_to_k_s_hat);
    ec_new(g_to_hash);
    ec_new(g_to_sk_hash);
    ec_new(g_to_gamma_2k);
    ec_new(g_to_k_gamma);
    cl_ciphertext_new(ctx_s_hat_from_t);
    zk_proof_new(pi_2dl);
    // Deserialize the data from the message.
    char ct_str[RLC_CL_CIPHERTEXT_SIZE];
    memcpy(ct_str, data, RLC_CL_CIPHERTEXT_SIZE);
    ctx_s_hat_from_t->c1 = gp_read_str(ct_str);
    memcpy(ct_str, data + RLC_CL_CIPHERTEXT_SIZE, RLC_CL_CIPHERTEXT_SIZE);
    ctx_s_hat_from_t->c2 = gp_read_str(ct_str);
    ec_read_bin(g_to_k_gamma, data + (2 * RLC_CL_CIPHERTEXT_SIZE), RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_2dl->a, data + (2 * RLC_CL_CIPHERTEXT_SIZE) + RLC_EC_SIZE_COMPRESSED, RLC_EC_SIZE_COMPRESSED);
    ec_read_bin(pi_2dl->b, data + (2 * RLC_CL_CIPHERTEXT_SIZE) + (2 * RLC_EC_SIZE_COMPRESSED), RLC_EC_SIZE_COMPRESSED);
    bn_read_bin(pi_2dl->z, data + (2 * RLC_EC_SIZE_COMPRESSED) + (3 * RLC_EC_SIZE_COMPRESSED), RLC_BN_SIZE);
    
    if (zk_dhtuple_verify(pi_2dl, state->g_to_rand_from_t, state->g_to_the_alpha_times_beta_times_tau, g_to_k_gamma) == RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    // Decrypt the ciphertext.
    GEN s_hat_from_t;
    if (cl_dec(&s_hat_from_t, ctx_s_hat_from_t, state->alice_cl_sk, state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    bn_read_str(plain_s_hat_from_t, GENtostr(s_hat_from_t), strlen(GENtostr(s_hat_from_t)), 10);
    ec_curve_get_ord(q);
    bn_mod(plain_s_hat_from_t, plain_s_hat_from_t, q);
    ec_mul(g_to_k_s_hat, state->g_to_rand_from_t, plain_s_hat_from_t);

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
    ec_mul(state->alice_tumbler_ec_pk->pk, state->tumbler_ec_pk->pk, state->alice_ec_sk->sk);

    ec_mul(g_to_gamma_2k, g_to_k_gamma, state->rand_for_t);
    ec_get_x(r_sigma_at, g_to_gamma_2k);
    bn_mod(r_sigma_at, r_sigma_at, q);
    ec_mul(g_to_sk_hash, state->alice_tumbler_ec_pk->pk, r_sigma_at);
    ec_add(g_to_sk_hash, g_to_sk_hash, g_to_hash);
    
    if (ec_cmp(g_to_k_s_hat, g_to_sk_hash) != RLC_EQ) {
      RLC_THROW(ERR_CAUGHT);
    }
    bn_mod_inv(inv_k, state->rand_for_t, q);
    bn_mul(plain_s_hat_from_t, plain_s_hat_from_t, inv_k);
    bn_mod(plain_s_hat_from_t, plain_s_hat_from_t, q);
    bn_copy(state->s_hat_from_t, plain_s_hat_from_t);

    // Build and define the message.
    char *msg_type = "payment_presig";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(payment_presig_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    bn_write_bin(payment_presig_msg->data, RLC_BN_SIZE, plain_s_hat_from_t);

    memcpy(payment_presig_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, payment_presig_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t payment_presig;
    int rc = zmq_msg_init_size(&payment_presig, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&payment_presig), serialized_message, total_msg_length);
    rc = zmq_msg_send(&payment_presig, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(e);
    bn_free(plain_s_hat_from_t);
    bn_free(r_sigma_at);
    bn_free(inv_k);
    ec_free(g_to_k_s_hat);
    ec_free(g_to_hash);
    ec_free(g_to_sk_hash);
    ec_free(g_to_gamma_2k);
    ec_free(g_to_k_gamma);
    cl_ciphertext_free(ctx_s_hat_from_t);
    zk_proof_free(pi_2dl);
    if (payment_presig_msg != NULL) message_free(payment_presig_msg);
    if (serialized_message != NULL) free(serialized_message);

  }

  return result_status;
}

int payment_sig_handler(alice_state_t state, void *socket, uint8_t *data) {
  if (state == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  bn_t q, gamma, tau_inverse, s_hat_from_t_inverse; //tau_inverse

  bn_null(q);    
  bn_null(gamma);
  bn_null(tau_inverse);
  bn_null(s_hat_from_t_inverse);

  RLC_TRY {
    bn_new(q);    
    bn_new(gamma);
    bn_new(tau_inverse);
    bn_new(s_hat_from_t_inverse);        
    bn_read_bin(state->sigma_s_at, data, RLC_BN_SIZE);

    ec_curve_get_ord(q);
    bn_mod_inv(s_hat_from_t_inverse, state->s_hat_from_t, q);
    bn_mul(gamma, state->sigma_s_at, s_hat_from_t_inverse);
    bn_mod_inv(gamma, gamma, q);
    bn_mod_inv(tau_inverse, state->tau, q);
    bn_mul(state->alpha_times_beta, gamma, tau_inverse);
    bn_mod(state->alpha_times_beta, state->alpha_times_beta, q);
    
    PUZZLE_SOLVED = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);      
    bn_free(gamma);
    bn_free(tau_inverse);
    bn_free(s_hat_from_t_inverse);

  }
 
  return result_status;
}

int puzzle_solution_share(alice_state_t state, void *socket) {
  if (state == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;
  uint8_t *serialized_message = NULL;

  message_t puzzle_solution_share_msg;
  message_null(puzzle_solution_share_msg);

  RLC_TRY {
    // Build and define the message.
    char *msg_type = "puzzle_solution_share";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = RLC_BN_SIZE + RLC_BN_SIZE;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(puzzle_solution_share_msg, msg_type_length, msg_data_length);
    
    // Serialize the data for the message.
    bn_write_bin(puzzle_solution_share_msg->data, RLC_BN_SIZE, state->alpha_times_beta);

    // Serialize the message.
    memcpy(puzzle_solution_share_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, puzzle_solution_share_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t puzzle_solution_share;
    int rc = zmq_msg_init_size(&puzzle_solution_share, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&puzzle_solution_share), serialized_message, total_msg_length);
    rc = zmq_msg_send(&puzzle_solution_share, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (puzzle_solution_share_msg != NULL) message_free(puzzle_solution_share_msg);
    if (serialized_message != NULL) free(serialized_message);
  }

  return result_status;
}

int main(void)
{
  init();
  int result_status = RLC_OK;
  REGISTRATION_COMPLETED = 0;
  PUZZLE_SHARED = 0;
  PUZZLE_SOLVED = 0;

  long long start_time, start_time_1, stop_time, total_time, total_time_alice;

  alice_state_t state;
  alice_state_null(state);

  // Socket to talk to other parties.
  void *context = zmq_ctx_new();
  if (!context) {
    fprintf(stderr, "Error: could not create a context.\n");
    exit(1);
  }

  printf("Connecting to Tumbler...\n\n");
  void *socket = zmq_socket(context, ZMQ_REQ);
  if (!socket) {
    fprintf(stderr, "Error: could not create a socket.\n");
    exit(1);
  }

  int rc = zmq_connect(socket, TUMBLER_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind the socket.\n");
    exit(1);
  }

  RLC_TRY {
    alice_state_new(state);

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    if (read_keys_from_file_alice_bob(ALICE_KEY_FILE_PREFIX,
                                      state->alice_ec_sk,
                                      state->alice_ec_pk,
                                      state->tumbler_ec_pk,
                                      state->tumbler_ps_pk,
                                      state->tumbler_cl_pk) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    start_time = ttimer();
    if (registration(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!REGISTRATION_COMPLETED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("Registration time: %.5f sec\n", total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
    }

    printf("Connecting to Bob...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, BOB_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Bob.\n");
      exit(1);
    }

    if (token_share(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("Registration time plus token share: %.5f sec\n", total_time / CLOCK_PRECISION);

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

    rc = zmq_bind(socket, ALICE_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not bind the socket.\n");
      exit(1);
    }

    while (!PUZZLE_SHARED) {
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
      fprintf(stderr, "Error: could not connect to Tumbler.\n");
      exit(1);
    }

    start_time_1 = ttimer();
    if (payment_init(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!PUZZLE_SOLVED) {
      if (receive_message(state, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    stop_time = ttimer();
    total_time = stop_time - start_time_1;
    printf("Puzzle solver time: %.5f sec\n", total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      exit(1);
    }

    printf("Connecting to Bob...\n\n");
    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_connect(socket, BOB_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to Bob.\n");
      exit(1);
    }

    if (puzzle_solution_share(state, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    stop_time = ttimer();
    total_time = stop_time - start_time_1;
    total_time_alice = stop_time - start_time;
    printf("Puzzle solver and solution share time: %.5f sec\n", total_time / CLOCK_PRECISION);
    printf("\nTotal time of Alice: %.5f sec\n", total_time_alice / CLOCK_PRECISION);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    alice_state_free(state);
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

  clean();

  return result_status;
}