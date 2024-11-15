**Source Code Description for “P2C2T: Preserving the Privacy of Cross-Chain Transfer”**  
[Link to Paper](https://eprint.iacr.org/2024/1467)

**1. Testing Off-Chain Overhead of P2C2T via `P2C2T_OFFCHAIN`**  
The project `P2C2T_OFFCHAIN` builds upon the framework of the A<sup>2</sup>L project ([A<sup>2</sup>L GitHub](https://github.com/etairi/A2L)) and requires the same dependencies. To run it, follow these steps:

1.1. Navigate to the directory `.../P2C2T_OFFCHAIN/build`:
```bash
rm -rf *
cmake ../
make
```

1.2. Then, go to `.../P2C2T_OFFCHAIN/bin` and execute:
```bash
./wrapper
```

The results (e.g., `P2C2T_OFFCHAIN_results.txt`) can be used to derive the off-chain overhead of P2C2T. Notably, in this project, "alice," "bob," and "tumbler" correspond to the sender, receiver, and hub in the P2C2T paper, respectively. The results exclude some one-time operations in the system setup phase, which can be tested by adding the corresponding codes in `P2C2T_OFFCHAIN`, though this is not elaborated here for brevity.

**2. Conducting Cross-Chain Transfers Using Bitcoin and Litecoin Testnets**  
Each cross-chain transfer consists of four on-chain payments: two transactions (a lock transaction and a transfer transaction) on each testnet. The `Pycryptotools` library ([Pycryptotools GitHub](https://github.com/primal100/pybitcointools)) is used for all payments.

To perform a cross-chain transfer, combine the hardcoded version of the `P2C2T_OFFCHAIN` project (referred to as `P2C2T_hardcode`) with the executable files in the `P2C2T_ONCHAIN` folder using the following steps:

2.1. **Generate Shared Addresses**  
Run `test_new_address.py` to derive shared addresses between senders and the hub, and `test_new_address_LTC.py` for shared addresses between the hub and receivers. The term “joint_pk” in both files can be derived from `P2C2T_hardcode`, as shown in the example output `P2C2T_hardcode_results.txt`.

2.2. **Perform Lock Transactions**  
Senders can send coins to the shared addresses by running `test_pay_new_address_1.py`, while the hub runs `test_pay_new_address_LTC_1.py`.

2.3. **Perform Transfer Transactions**  
Execute the following steps:

2.3.1. **Obtain Off-Chain Hardcore Information for Senders and the Hub**  
Compute the required inputs (corresponding to `e`, `k_s`, and `k_h1` in `test_e_k_gen_2AS_1.py`) of ECDSA-based two-party adaptor signatures between senders and the hub by running `test_e_k_gen_2AS_1.py`. Replace the corresponding holder information in `alice.c` and `tumbler.c` of `P2C2T_hardcode` with these inputs.

2.3.2. **Conduct Payment from the Shared Address to the Hub**  
Run `P2C2T_hardcode` to obtain the ECDSA-based two-party adaptor signature `(r,s)` from `tumbler.c`. Input `(r,s)` into `test_e_k_gen_2AS_1.py` to execute the intended payment.

2.3.3. **Obtain Off-Chain Hardcore Information for the Hub and Receivers**  
Compute the required inputs (corresponding to `e`, `k_r`, and `k_h2` in `test_e_k_gen_2AS_1_LTC.py`) of ECDSA-based two-party adaptor signatures between the hub and receivers by running `test_e_k_gen_2AS_1_LTC.py`. Replace the corresponding holder information in `tumbler.c` and `bob.c` of `P2C2T_hardcode` with these inputs.

2.3.4. **Conduct Payment from the Shared Address to Receivers**  
Run `P2C2T_hardcode` to obtain the ECDSA-based two-party adaptor signature `(r,s)` from `bob.c`. Input `(r,s)` into `test_e_k_gen_2AS_1_LTC.py` to execute the intended payment.

**Warning**  
All code provided here is developed for experimentation purposes and has not been reviewed by qualified cryptographers. Use at your own risk.
