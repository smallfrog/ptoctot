#ifndef P2C2T_ECDSA_INCLUDE_TYPES
#define P2C2T_ECDSA_INCLUDE_TYPES

#include "relic/relic.h"
#include "pari/pari.h"
#include "gmp.h"
typedef struct {
  char *type;
  uint8_t *data;
} message_st;

typedef message_st *message_t;

#define message_null(message) message = NULL;

#define message_new(message, type_length, data_length)                  \
  do {                                                                  \
    message = malloc(sizeof(message_st));                               \
    if (message == NULL) {                                              \
      RLC_THROW(ERR_NO_MEMORY);                                         \
    }                                                                   \
    (message)->type = malloc(sizeof(char) * type_length);               \
    if ((message)->type == NULL) {                                      \
      RLC_THROW(ERR_NO_MEMORY);                                         \
    }                                                                   \
    (message)->data = malloc(sizeof(uint8_t) * data_length);            \
    if ((message)->data == NULL) {                                      \
      RLC_THROW(ERR_NO_MEMORY);                                         \
    }                                                                   \
  } while (0)

#define message_free(message)                                           \
  do {                                                                  \
    free((message)->type);                                              \
    free((message)->data);                                              \
    free(message);                                                      \
    message = NULL;                                                     \
  } while (0)

typedef struct {
  ec_t a;
  ec_t b;
  bn_t z;
} zk_proof_st;

typedef zk_proof_st *zk_proof_t;

#define zk_proof_null(proof) proof = NULL;

#define zk_proof_new(proof)                   \
  do {                                        \
    proof = malloc(sizeof(zk_proof_st));      \
    if (proof == NULL) {                      \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    ec_new((proof)->a);                       \
    ec_new((proof)->b);                       \
    bn_new((proof)->z);                       \
  } while (0)

#define zk_proof_free(proof)                  \
  do {                                        \
    ec_free((proof)->a);                      \
    ec_free((proof)->b);                      \
    bn_free((proof)->z);                      \
    free(proof);                              \
    proof = NULL;                             \
  } while (0)

typedef struct {
  GEN t1;
  ec_t t2;
  GEN t3;
  GEN u1;
  GEN u2;
} zk_proof_cldl_st;

typedef zk_proof_cldl_st *zk_proof_cldl_t;

#define zk_proof_cldl_null(proof) proof = NULL;

#define zk_proof_cldl_new(proof)              \
  do {                                        \
    proof = malloc(sizeof(zk_proof_cldl_st)); \
    if (proof == NULL) {                      \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    ec_new((proof)->t2);                      \
  } while (0)

#define zk_proof_cldl_free(proof)             \
  do {                                        \
    ec_free((proof)->t2);                     \
    free(proof);                              \
    proof = NULL;                             \
  } while (0)

typedef struct {
  bn_t c;
  ec_t r;
} commit_st;

typedef commit_st *commit_t;

#define commit_null(commit) commit = NULL;

#define commit_new(commit)                    \
  do {                                        \
    commit = malloc(sizeof(commit_st));       \
    if (commit == NULL) {                     \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    bn_new((commit)->c);                      \
    ec_new((commit)->r);                      \
  } while (0)

#define commit_free(commit)                   \
  do {                                        \
    bn_free((commit)->c);                     \
    ec_free((commit)->r);                     \
    free(commit);                             \
    commit = NULL;                            \
  } while (0)

typedef struct {
  g1_t c;
} pedersen_com_st;

typedef pedersen_com_st *pedersen_com_t;

#define pedersen_com_null(com) com = NULL;

#define pedersen_com_new(com)                 \
  do {                                        \
    com = malloc(sizeof(pedersen_com_st));    \
    if (com == NULL) {                        \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    g1_new((com)->c);                         \
  } while (0)

#define pedersen_com_free(com)                \
  do {                                        \
    g1_free((com)->c);                        \
    free(com);                                \
    com = NULL;                               \
  } while (0)

typedef struct {
  bn_t r;
  bn_t m;
} pedersen_decom_st;

typedef pedersen_decom_st *pedersen_decom_t;

#define pedersen_decom_null(decom) decom = NULL;

#define pedersen_decom_new(decom)             \
  do {                                        \
    decom = malloc(sizeof(pedersen_decom_st));\
    if (decom == NULL) {                      \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    bn_new((decom)->r);                       \
    bn_new((decom)->m);                       \
  } while (0)

#define pedersen_decom_free(decom)            \
  do {                                        \
    bn_free((decom)->r);                      \
    bn_free((decom)->m);                      \
    free(decom);                              \
    decom = NULL;                             \
  } while (0)

typedef struct {
    int degree; 
    bn_t *coefficients;
} polynomial_param_st;

typedef polynomial_param_st *polynomial_param_t;

#define polynomial_param_null(param) param = NULL;

#define polynomial_param_new(param, degree_para) \
  do { \
    param = malloc(sizeof(polynomial_param_st)); \
    if (param == NULL) { \
      RLC_THROW(ERR_NO_MEMORY); \
    } \
    (param)->degree = degree_para; \
    (param)->coefficients = malloc(sizeof(bn_t) * (degree_para + 1)); \
    if ((param)->coefficients == NULL) { \
      free(param); \
      RLC_THROW(ERR_NO_MEMORY); \
    } \
    for (int i = 0; i < degree_para + 1; i++) { \
      bn_new((param)->coefficients[i]); \
    } \
  } while (0)


#define polynomial_param_free(param)            \
  do {                                          \
    for (int i=0; i < (param)->degree + 1; i++) {\
      bn_free((param)->coefficients[i]); \
    }                           \
    free(param->coefficients);\
    free((para)->degree);                               \
    free(param);                              \
    param = NULL;                             \
  } while (0)


typedef struct {
  bn_t T;
  bn_t N;
  bn_t g;
  bn_t h;
} lhtlp_param_st;

typedef lhtlp_param_st *lhtlp_param_t;

#define lhtlp_param_null(param) param = NULL;

#define lhtlp_param_new(param)             \
  do {                                        \
    param = malloc(sizeof(lhtlp_param_st));\
    if (param == NULL) {                      \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    bn_new((param)->T);                       \
    bn_new((param)->N);                       \
    bn_new((param)->g);                       \
    bn_new((param)->h);                       \
  } while (0)

#define lhtlp_param_free(param)            \
  do {                                        \
    bn_free((param)->T);                      \
    bn_free((param)->N);                      \
    bn_free((param)->g);                      \
    bn_free((param)->h);                      \
    free(param);                              \
    param = NULL;                             \
  } while (0)

typedef struct {
  bn_t u;
  mpz_t v;
} lhtlp_puzzle_st;

typedef lhtlp_puzzle_st *lhtlp_puzzle_t;

#define lhtlp_puzzle_null(puzzle) puzzle = NULL;

#define lhtlp_puzzle_new(puzzle)             \
  do {                                        \
    puzzle = malloc(sizeof(lhtlp_puzzle_st));\
    if (puzzle == NULL) {                      \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    bn_new((puzzle)->u);                       \
    mpz_init((puzzle)->v);                       \
  } while (0)

#define lhtlp_puzzle_free(puzzle)            \
  do {                                        \
    bn_free((puzzle)->u);                      \
    mpz_clear((puzzle)->v);                      \
    free(puzzle);                              \
    puzzle = NULL;                             \
  } while (0)

typedef struct {
  lhtlp_puzzle_t D;
  bn_t V;
  bn_t W;
} pi_lhtlp_range_st;

typedef pi_lhtlp_range_st *pi_lhtlp_range_t;

#define pi_lhtlp_range_null(lhtlp_range) lhtlp_range = NULL;

#define pi_lhtlp_range_new(lhtlp_range)             \
  do {                                        \
    lhtlp_range = malloc(sizeof(pi_lhtlp_range_st));\
    if (lhtlp_range == NULL) {                      \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    lhtlp_puzzle_new((lhtlp_range)->D);                       \
    bn_new((lhtlp_range)->V);                       \
    bn_new((lhtlp_range)->W);                       \
  } while (0)

#define pi_lhtlp_range_free(lhtlp_range)            \
  do {                                        \
    lhtlp_puzzle_free((lhtlp_range)->D);                      \
    bn_free((lhtlp_range)->V);                      \
    bn_free((lhtlp_range)->W);                      \
    free(lhtlp_range);                              \
    lhtlp_range = NULL;                             \
  } while (0)

typedef struct {
  bn_t r;
  lhtlp_puzzle_t *Ds;
  bn_t *Vs;
  bn_t *Ws;
} pis_lhtlp_range_st;

typedef pis_lhtlp_range_st *pis_lhtlp_range_t;

#define pis_lhtlp_range_null(lhtlp_range) lhtlp_range = NULL;

#define pis_lhtlp_range_new(lhtlp_range, statis_para)             \
  do {                                        \
    lhtlp_range = malloc(sizeof(pis_lhtlp_range_st));\
    if (lhtlp_range == NULL) {                      \
      RLC_THROW(ERR_NO_MEMORY);               \
    }                                         \
    bn_new((lhtlp_range)->r);                       \
    (lhtlp_range)->Ds = malloc(sizeof(lhtlp_puzzle_t) * statis_para);               \
    if ((lhtlp_range)->Ds == NULL) {                                      \
      RLC_THROW(ERR_NO_MEMORY);                                         \
    }                                                                   \
    (lhtlp_range)->Vs = malloc(sizeof(bn_t) * statis_para);               \
    if ((lhtlp_range)->Vs == NULL) {                                      \
      RLC_THROW(ERR_NO_MEMORY);                                         \
    }                                                                   \
    (lhtlp_range)->Ws = malloc(sizeof(bn_t) * statis_para);               \
    if ((lhtlp_range)->Ws == NULL) {                                      \
      RLC_THROW(ERR_NO_MEMORY);                                         \
    }  \
  } while (0)

#define pis_lhtlp_range_free(lhtlp_range,statis_para)            \
  do {                                        \
    bn_free((lhtlp_range)->r);                       \
    free((lhtlp_range)->Ds);\
    free((lhtlp_range)->Vs);\
    free((lhtlp_range)->Ws);\
    free(lhtlp_range);                              \
  } while (0)
 
typedef struct {
  pedersen_com_t c;
  bn_t u;
  bn_t v;
} pedersen_com_zk_proof_st;

typedef pedersen_com_zk_proof_st *pedersen_com_zk_proof_t;

#define pedersen_com_zk_proof_null(proof) proof = NULL;

#define pedersen_com_zk_proof_new(proof)              \
  do {                                                \
    proof = malloc(sizeof(pedersen_com_zk_proof_st)); \
    if (proof == NULL) {                              \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
    pedersen_com_new((proof)->c);                     \
    bn_new((proof)->u);                               \
    bn_new((proof)->v);                               \
  } while (0)

#define pedersen_com_zk_proof_free(proof)             \
  do {                                                \
    pedersen_com_free((proof)->c);                    \
    bn_free((proof)->u);                              \
    bn_free((proof)->v);                              \
    free(proof);                                      \
    proof = NULL;                                     \
  } while (0)

typedef struct {
  GEN Delta_K;  // fundamental discriminant
  GEN E;        // the secp256k1 elliptic curve
  GEN q;        // the order of the elliptic curve
  GEN G;        // the generator of the elliptic curve group
  GEN g_q;      // the generator of G^q
  GEN bound;    // the bound for exponentiation
} cl_params_st;

typedef cl_params_st *cl_params_t;

#define cl_params_null(params) params = NULL;

#define cl_params_new(params)                         \
  do {                                                \
    params = malloc(sizeof(cl_params_st));            \
    if (params == NULL) {                             \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
  } while (0)

#define cl_params_free(params)                        \
  do {                                                \
    free(params);                                     \
    params = NULL;                                    \
  } while (0)

typedef struct {
  GEN c1;
  GEN c2;
  GEN r;
} cl_ciphertext_st;

typedef cl_ciphertext_st *cl_ciphertext_t;

#define cl_ciphertext_null(ciphertext) ciphertext = NULL;

#define cl_ciphertext_new(ciphertext)                 \
  do {                                                \
    ciphertext = malloc(sizeof(cl_ciphertext_st));    \
    if (ciphertext == NULL) {                         \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
  } while (0)

#define cl_ciphertext_free(ciphertext)                \
  do {                                                \
    free(ciphertext);                                 \
    ciphertext = NULL;                                \
  } while (0)

typedef struct {
  GEN sk;
} cl_secret_key_st;

typedef cl_secret_key_st *cl_secret_key_t;

#define cl_secret_key_null(secret_key) secret_key = NULL;

#define cl_secret_key_new(secret_key)                 \
  do {                                                \
    secret_key = malloc(sizeof(cl_secret_key_st));    \
    if (secret_key == NULL) {                         \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
  } while (0)

#define cl_secret_key_free(secret_key)                \
  do {                                                \
    free(secret_key);                                 \
    secret_key = NULL;                                \
  } while (0)


typedef struct {
  GEN pk;
} cl_public_key_st;

typedef cl_public_key_st *cl_public_key_t;

#define cl_public_key_null(public_key) public_key = NULL;

#define cl_public_key_new(public_key)                 \
  do {                                                \
    public_key = malloc(sizeof(cl_public_key_st));    \
    if (public_key == NULL) {                         \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
  } while (0)

#define cl_public_key_free(public_key)                \
  do {                                                \
    free(public_key);                                 \
    public_key = NULL;                                \
  } while (0)

typedef struct {
  bn_t sk;
} ec_secret_key_st;

typedef ec_secret_key_st *ec_secret_key_t;

#define ec_secret_key_null(secret_key) secret_key = NULL;

#define ec_secret_key_new(secret_key)                 \
  do {                                                \
    secret_key = malloc(sizeof(ec_secret_key_st));    \
    if (secret_key == NULL) {                         \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
    bn_new((secret_key)->sk);                         \
  } while (0)

#define ec_secret_key_free(secret_key)                \
  do {                                                \
    bn_free((secret_key)->sk);                        \
    free(secret_key);                                 \
    secret_key = NULL;                                \
  } while (0)

typedef struct {
  ec_t pk;
} ec_public_key_st;

typedef ec_public_key_st *ec_public_key_t;

#define ec_public_key_null(public_key) public_key = NULL;

#define ec_public_key_new(public_key)                 \
  do {                                                \
    public_key = malloc(sizeof(ec_public_key_st));    \
    if (public_key == NULL) {                         \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
    ec_new((public_key)->pk);                         \
  } while (0)

#define ec_public_key_free(public_key)                \
  do {                                                \
    ec_free((public_key)->pk);                        \
    free(public_key);                                 \
    public_key = NULL;                                \
  } while (0)

typedef struct {
  bn_t r;
  bn_t s;
  ec_t R;
  zk_proof_t pi;
} ecdsa_signature_st;

typedef ecdsa_signature_st *ecdsa_signature_t;

#define ecdsa_signature_null(signature) signature = NULL;

#define ecdsa_signature_new(signature)                \
  do {                                                \
    signature = malloc(sizeof(ecdsa_signature_st));   \
    if (signature == NULL) {                          \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
    bn_new((signature)->r);                           \
    bn_new((signature)->s);                           \
    ec_new((signature)->R);                           \
    zk_proof_new((signature)->pi);                    \
  } while (0)

#define ecdsa_signature_free(signature)               \
  do {                                                \
    bn_free((signature)->r);                          \
    bn_free((signature)->s);                          \
    ec_free((signature)->R);                          \
    zk_proof_free((signature)->pi);                   \
    free(signature);                                  \
    signature = NULL;                                 \
  } while (0)

typedef struct {
  g1_t sigma_1;
  g1_t sigma_2;
} ps_signature_st;

typedef ps_signature_st *ps_signature_t;

#define ps_signature_null(signature) signature = NULL;

#define ps_signature_new(signature)                   \
  do {                                                \
    signature = malloc(sizeof(ps_signature_st));      \
    if (signature == NULL) {                          \
      RLC_THROW(ERR_NO_MEMORY);                       \
    }                                                 \
    g1_new((signature)->sigma_1);                     \
    g1_new((signature)->sigma_2);                     \
  } while (0)

#define ps_signature_free(signature)                  \
  do {                                                \
    g1_free((signature)->sigma_1);                    \
    g1_free((signature)->sigma_2);                    \
    free(signature);                                  \
    signature = NULL;                                 \
  } while (0)

typedef struct {
  g1_t Y_1;
  g2_t X_2;
  g2_t Y_2;
} ps_public_key_st;

typedef ps_public_key_st *ps_public_key_t;

#define ps_public_key_null(public_key) public_key = NULL;

#define ps_public_key_new(public_key)                   \
  do {                                                  \
    public_key = malloc(sizeof(ps_public_key_st));      \
    if (public_key == NULL) {                           \
      RLC_THROW(ERR_NO_MEMORY);                         \
    }                                                   \
    g1_new((public_key)->Y_1);                          \
    g2_new((public_key)->X_2);                          \
    g2_new((public_key)->Y_2);                          \
  } while (0)

#define ps_public_key_free(public_key)                  \
  do {                                                  \
    g1_free((public_key)->Y_1);                         \
    g2_free((public_key)->X_2);                         \
    g2_free((public_key)->Y_2);                         \
    free(public_key);                                   \
    public_key = NULL;                                  \
  } while (0)

typedef struct {
  g1_t X_1;
} ps_secret_key_st;

typedef ps_secret_key_st *ps_secret_key_t;

#define ps_secret_key_null(secret_key) secret_key = NULL;

#define ps_secret_key_new(secret_key)                   \
  do {                                                  \
    secret_key = malloc(sizeof(ps_secret_key_st));      \
    if (secret_key == NULL) {                           \
      RLC_THROW(ERR_NO_MEMORY);                         \
    }                                                   \
    g1_new((secret_key)->X_1);                          \
  } while (0)

#define ps_secret_key_free(secret_key)                  \
  do {                                                  \
    g1_free((secret_key)->X_1);                         \
    free(secret_key);                                   \
    secret_key = NULL;                                  \
  } while (0)

#endif