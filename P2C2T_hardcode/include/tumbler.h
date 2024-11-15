#ifndef P2C2T_ECDSA_INCLUDE_TUMBLER
#define P2C2T_ECDSA_INCLUDE_TUMBLER

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "zmq.h"
#include "types.h"

#define TUMBLER_ENDPOINT  "tcp://*:8181"

typedef enum {
  REGISTRATION_Z,
  REGISTRATION_TID,
  PROMISE_INIT,
  PROMISE_ZKDL,
  PROMISE_PRESIG,  
  PAYMENT_INIT,
  PAYMENT_DECOM,
  PAYMENT_PRESIG,
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "registration_z", REGISTRATION_Z },
  { "registration_tid", REGISTRATION_TID},
  { "promise_init", PROMISE_INIT },
  { "promise_zkdl", PROMISE_ZKDL },
  { "promise_presig", PROMISE_PRESIG },
  { "payment_init", PAYMENT_INIT },
  { "payment_decom", PAYMENT_DECOM },
  { "payment_presig", PAYMENT_PRESIG },
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  ec_secret_key_t tumbler_ec_sk;
  ec_public_key_t tumbler_ec_pk;
  ec_secret_key_t tumbler_ec_sk2;
  ec_public_key_t tumbler_ec_pk2;  
  ec_public_key_t tumbler_bob_ec_pk;
  ec_public_key_t tumbler_alice_ec_pk;
  ec_public_key_t alice_ec_pk;
  ec_public_key_t bob_ec_pk;
  ps_secret_key_t tumbler_ps_sk;
  ps_public_key_t tumbler_ps_pk;
  cl_secret_key_t tumbler_cl_sk;
  cl_public_key_t tumbler_cl_pk;
  cl_public_key_t alice_cl_pk;
  cl_public_key_t bob_cl_pk;
  cl_params_t cl_params;
  bn_t gamma;
  bn_t gamma_check;
  bn_t alpha;
  bn_t rand_for_bob;
  bn_t rand_for_a;
  bn_t com_c_from_a;
  ec_t g_to_the_alpha;
  ec_t go_to_rand_for_bob;
  ec_t go_to_rand_from_bob;
  ec_t g_to_rand_for_a;
  ec_t g_to_rand_from_a;
  cl_ciphertext_t ctx_alpha;
  cl_ciphertext_t ctx_alpha_check;
  cl_ciphertext_t ctx_sk_from_a;
  cl_ciphertext_t ctx_sk_from_b;
  ecdsa_signature_t sigma_r;
  ecdsa_signature_t sigma_tr;
  ecdsa_signature_t sigma_s;
  ecdsa_signature_t sigma_ts;
  ecdsa_signature_t sigma_tb;
  ecdsa_signature_t sigma_ta;
  commit_t com_for_bob;
  lhtlp_param_t lhtlp_param;

} tumbler_state_st;

typedef tumbler_state_st *tumbler_state_t;

#define tumbler_state_null(state) state = NULL;

#define tumbler_state_new(state)                          \
  do {                                                    \
    state = malloc(sizeof(tumbler_state_st));             \
    if (state == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                     \
    ec_secret_key_new((state)->tumbler_ec_sk);            \
    ec_public_key_new((state)->tumbler_ec_pk);            \
    ec_secret_key_new((state)->tumbler_ec_sk2);            \
    ec_public_key_new((state)->tumbler_ec_pk2);            \
    ec_public_key_new((state)->tumbler_bob_ec_pk);            \
    ec_public_key_new((state)->tumbler_alice_ec_pk);            \
    ec_public_key_new((state)->alice_ec_pk);              \
    ec_public_key_new((state)->bob_ec_pk);                \
    ps_secret_key_new((state)->tumbler_ps_sk);            \
    ps_public_key_new((state)->tumbler_ps_pk);            \
    cl_secret_key_new((state)->tumbler_cl_sk);            \
    cl_public_key_new((state)->tumbler_cl_pk);            \
    cl_public_key_new((state)->alice_cl_pk);            \
    cl_public_key_new((state)->bob_cl_pk);            \
    cl_params_new((state)->cl_params);                    \
    bn_new((state)->gamma);                               \
    bn_new((state)->gamma_check);                               \
    bn_new((state)->alpha);                               \
    bn_new((state)->rand_for_bob);                               \
    bn_new((state)->rand_for_a);                               \
    bn_new((state)->com_c_from_a);                               \
    ec_new((state)->g_to_the_alpha);                      \
    ec_new((state)->go_to_rand_for_bob);                      \
    ec_new((state)->go_to_rand_from_bob);                      \
    ec_new((state)->g_to_rand_for_a);                      \
    ec_new((state)->g_to_rand_from_a);                      \
    cl_ciphertext_new((state)->ctx_alpha);                \
    cl_ciphertext_new((state)->ctx_alpha_check);                \
    cl_ciphertext_new((state)->ctx_sk_from_a);                \
    cl_ciphertext_new((state)->ctx_sk_from_b);                \
    ecdsa_signature_new((state)->sigma_r);                \
    ecdsa_signature_new((state)->sigma_tr);               \
    ecdsa_signature_new((state)->sigma_s);                \
    ecdsa_signature_new((state)->sigma_ts);               \
    ecdsa_signature_new((state)->sigma_tb);               \
    ecdsa_signature_new((state)->sigma_ta);               \
    commit_new((state)->com_for_bob);               \
    lhtlp_param_new((state)->lhtlp_param);               \
  } while (0)

#define tumbler_state_free(state)                         \
  do {                                                    \
    ec_secret_key_free((state)->tumbler_ec_sk);           \
    ec_public_key_free((state)->tumbler_ec_pk);           \
    ec_secret_key_free((state)->tumbler_ec_sk2);           \
    ec_public_key_free((state)->tumbler_ec_pk2);           \
    ec_public_key_free((state)->tumbler_bob_ec_pk);           \
    ec_public_key_free((state)->tumbler_alice_ec_pk);           \
    ec_public_key_free((state)->alice_ec_pk);             \
    ec_public_key_free((state)->bob_ec_pk);               \
    ps_secret_key_free((state)->tumbler_ps_sk);           \
    ps_public_key_free((state)->tumbler_ps_pk);           \
    cl_secret_key_free((state)->tumbler_cl_sk);           \
    cl_public_key_free((state)->tumbler_cl_pk);           \
    cl_public_key_free((state)->alice_cl_pk);           \
    cl_public_key_free((state)->bob_cl_pk);           \
    cl_params_free((state)->cl_params);                   \
    bn_free((state)->gamma);                              \
    bn_free((state)->gamma_check);                              \
    bn_free((state)->alpha);                              \
    bn_free((state)->rand_for_bob);                               \
    bn_free((state)->rand_for_a);                               \
    bn_free((state)->com_c_from_a);                               \
    ec_free((state)->g_to_the_alpha);                     \
    ec_free((state)->go_to_rand_for_bob);                      \
    ec_free((state)->go_to_rand_from_bob);                      \
    ec_free((state)->g_to_rand_for_a);                      \
    ec_free((state)->g_to_rand_from_a);                      \
    cl_ciphertext_free((state)->ctx_alpha);               \
    cl_ciphertext_free((state)->ctx_alpha_check);               \
    cl_ciphertext_free((state)->ctx_sk_from_a);               \
    cl_ciphertext_free((state)->ctx_sk_from_b);               \
    ecdsa_signature_free((state)->sigma_r);               \
    ecdsa_signature_free((state)->sigma_tr);              \
    ecdsa_signature_free((state)->sigma_s);               \
    ecdsa_signature_free((state)->sigma_ts);              \
    ecdsa_signature_free((state)->sigma_tb);              \
    ecdsa_signature_free((state)->sigma_ta);              \
    lhtlp_param_free((state)->lhtlp_param);               \
    commit_free((state)->com_for_bob);               \
    free(state);                                          \
    state = NULL;                                         \
  } while (0)

typedef int (*msg_handler_t)(tumbler_state_t, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(tumbler_state_t state, void *socket, zmq_msg_t message);
int receive_message(tumbler_state_t state, void *socket);

int registration_handler(tumbler_state_t state, void *socket, uint8_t *data);
int registration_tid_handler(tumbler_state_t state, void *socket, uint8_t *data);
int promise_init_handler(tumbler_state_t state, void *socket, uint8_t *data);
int promise_zkdl_handler(tumbler_state_t state, void *socket, uint8_t *data);
int promise_presig_handler(tumbler_state_t state, void *socket, uint8_t *data);
int payment_init_handler(tumbler_state_t state, void *socket, uint8_t *data);
int payment_decom_handler(tumbler_state_t state, void *socket, uint8_t *data);
int payment_presig_handler(tumbler_state_t state, void *socket, uint8_t *data);

#endif