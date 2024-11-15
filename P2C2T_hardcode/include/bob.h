#ifndef P2C2T_ECDSA_INCLUDE_BOB
#define P2C2T_ECDSA_INCLUDE_BOB

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "zmq.h"
#include "types.h"

#define TUMBLER_ENDPOINT  "tcp://localhost:8181"
#define ALICE_ENDPOINT    "tcp://localhost:8182"
#define BOB_ENDPOINT      "tcp://*:8183"

typedef enum {
  TOKEN_SHARE,
  PROMISE_COM,
  PROMISE_DECOM,
  PROMISE_OVER,
  PUZZLE_SHARE_DONE,
  PUZZLE_SOLUTION_SHARE
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "token_share", TOKEN_SHARE },
  { "promise_com", PROMISE_COM },
  { "promise_decom", PROMISE_DECOM },
  { "promise_over", PROMISE_OVER },
  { "puzzle_share_done", PUZZLE_SHARE_DONE },
  { "puzzle_solution_share", PUZZLE_SOLUTION_SHARE }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  ec_secret_key_t bob_ec_sk;
  ec_public_key_t bob_ec_pk;
  ec_public_key_t bob_tumbler_ec_pk;
  ec_public_key_t tumbler_ec_pk;
  ec_public_key_t tumbler_ec_pk2;
  ps_public_key_t tumbler_ps_pk;
  cl_secret_key_t bob_cl_sk;
  cl_public_key_t bob_cl_pk;
  cl_public_key_t tumbler_cl_pk;
  cl_params_t cl_params;
  commit_t com;
  ec_t g_to_the_alpha;
  ec_t g_to_the_alpha_from_t;
  ec_t g_to_the_rand_from_t;
  cl_ciphertext_t ctx_alpha;
  cl_ciphertext_t ctx_alpha_check;
  cl_ciphertext_t ctx_alpha_from_t;
  cl_ciphertext_t ctx_sk_from_t;
  ecdsa_signature_t sigma_r;
  ecdsa_signature_t sigma_t;
  ecdsa_signature_t sigma_b_t_hat;
  bn_t beta;
  bn_t tid;
  bn_t rand_for_tumbler;
  bn_t com_c_from_tumbler;
  ps_signature_t sigma_tid;
  lhtlp_param_t lhtlp_param;
} bob_state_st;

typedef bob_state_st *bob_state_t;

#define bob_state_null(state) state = NULL;

#define bob_state_new(state)                                \
  do {                                                      \
    state = malloc(sizeof(bob_state_st));                   \
    if (state == NULL) {                                    \
      RLC_THROW(ERR_NO_MEMORY);                             \
    }                                                       \
    ec_secret_key_new((state)->bob_ec_sk);                  \
    ec_public_key_new((state)->bob_ec_pk);                  \
    ec_public_key_new((state)->bob_tumbler_ec_pk);                  \
    ec_public_key_new((state)->tumbler_ec_pk);              \
    ec_public_key_new((state)->tumbler_ec_pk2);              \
    ps_public_key_new((state)->tumbler_ps_pk);              \
    cl_secret_key_new((state)->bob_cl_sk);              \
    cl_public_key_new((state)->bob_cl_pk);              \
    cl_public_key_new((state)->tumbler_cl_pk);              \
    cl_params_new((state)->cl_params);                      \
    commit_new((state)->com);                               \
    ec_new((state)->g_to_the_alpha);                        \
    ec_new((state)->g_to_the_alpha_from_t);                        \
    ec_new((state)->g_to_the_rand_from_t);                        \
    cl_ciphertext_new((state)->ctx_alpha);                  \
    cl_ciphertext_new((state)->ctx_alpha_check);                  \
    cl_ciphertext_new((state)->ctx_alpha_from_t);                  \
    cl_ciphertext_new((state)->ctx_sk_from_t);                  \
    ecdsa_signature_new((state)->sigma_r);                  \
    ecdsa_signature_new((state)->sigma_t);                  \
    ecdsa_signature_new((state)->sigma_b_t_hat);                  \
    bn_new((state)->beta);                                  \
    bn_new((state)->tid);                                   \
    bn_new((state)->rand_for_tumbler);                                   \
    bn_new((state)->com_c_from_tumbler);                                   \
    ps_signature_new((state)->sigma_tid);                   \
    lhtlp_param_new((state)->lhtlp_param);               \
  } while (0)

#define bob_state_free(state)                               \
  do {                                                      \
    ec_secret_key_free((state)->bob_ec_sk);                 \
    ec_public_key_free((state)->bob_ec_pk);                 \
    ec_public_key_free((state)->bob_tumbler_ec_pk);                 \
    ec_public_key_free((state)->tumbler_ec_pk);             \
    ec_public_key_free((state)->tumbler_ec_pk2);             \
    ps_public_key_free((state)->tumbler_ps_pk);             \
    cl_secret_key_free((state)->bob_cl_sk);              \
    cl_public_key_free((state)->bob_cl_pk);              \
    cl_public_key_free((state)->tumbler_cl_pk);             \
    cl_params_free((state)->cl_params);                     \
    commit_free((state)->com);                              \
    ec_free((state)->g_to_the_alpha);                       \
    ec_free((state)->g_to_the_alpha_from_t);                       \
    ec_free((state)->g_to_the_rand_from_t);                       \
    cl_ciphertext_free((state)->ctx_alpha);                 \
    cl_ciphertext_free((state)->ctx_alpha_check);                 \
    cl_ciphertext_free((state)->ctx_alpha_from_t);                 \
    cl_ciphertext_free((state)->ctx_sk_from_t);                 \
    ecdsa_signature_free((state)->sigma_r);                 \
    ecdsa_signature_free((state)->sigma_t);                 \
    ecdsa_signature_free((state)->sigma_b_t_hat);                 \
    bn_free((state)->beta);                                 \
    bn_free((state)->tid);                                  \
    bn_free((state)->rand_for_tumbler);                                  \
    bn_free((state)->com_c_from_tumbler);                                  \
    ps_signature_free((state)->sigma_tid);                  \
    lhtlp_param_free((state)->lhtlp_param);               \
    free(state);                                            \
    state = NULL;                                           \
  } while (0)

typedef int (*msg_handler_t)(bob_state_t, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(bob_state_t state, void *socket, zmq_msg_t message);
int receive_message(bob_state_t state, void *socket);

int token_share_handler(bob_state_t state, void *socet, uint8_t *data);
int promise_init(bob_state_t state, void *socket);
int promise_com_handler(bob_state_t state, void *socket, uint8_t *data);
int promise_decom_handler(bob_state_t state, void *socket, uint8_t *data);
int promise_over_handler(bob_state_t state, void *socket, uint8_t *data);
int puzzle_share(bob_state_t state, void *socket);
int puzzle_share_done_handler(bob_state_t state, void *socket, uint8_t *data);
int puzzle_solution_share_handler(bob_state_t state, void *socet, uint8_t *data);

#endif