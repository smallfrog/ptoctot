from cryptos import *

def main():

    c = Litecoin(testnet=True)

    x_coord = int("66B7CA613CEB10BD14B390ED8A2964E14B9CB17CD612895D3E084F1DBFFAC85B", 16)
    y_coord = int("5AC06137630F098B3CFF6F906EFBC85EF0C85B593ECEFCE1D53C68650F7DC67C", 16)
    
    joint_pk = (x_coord, y_coord)
    pub_from_enc = encode_pubkey(joint_pk, "hex_compressed")

    inputs = c.unspent("mzuA3ArQC7eEbELjpajyUL6VUttgN9bo4i")
    print("\nFrom inputs:\n", inputs)
 
    outs = [{'value': 7400000, 'address': 'QZhwW8U8XqPGuspnUjx8Fzyx6AcMXckPQv'}]
    
    tx = c.mktx(inputs,outs)
    print("\nUnsigned transaction:\n", tx)
    tx_split = tx

    script = addr_to_pubkey_script("mzuA3ArQC7eEbELjpajyUL6VUttgN9bo4i")
    tx4 = signature_form(tx_split, 0, script, SIGHASH_ALL)      
    print("\nSigning transaction:\n", tx4)

    bin_txh = bin_txhash(tx4, SIGHASH_ALL)
    print("\nbin of txhash connecting with hashcode 1:\n", bin_txh)
    e = hash_to_int(bin_txh)
    print("\nint of txhash connecting with hashcode 1:\n", e)

    priv_r = "***"

    k_r = deterministic_generate_k(tx4, priv_r)
    print("\nk_r value:\n", k_r)

    priv_h2 = "***"

    k_h2 = deterministic_generate_k(tx4, priv_h2)
    print("\nk_h2 value:\n", k_h2)   
    
    v = 32
    r = int("83741DD8DFB27A63F90BA8024285517C4B83920C2725F34F90C805CEC328B88E",16)
    s = int("1B93018D6F1C6A453A1A5D8150DB60FC581D11A85273F53A6A32152BF732CB3E",16)
    rawsig = [v, r, s]
    
    res_sig_c = ecdsa_raw_verify(bin_txh, rawsig, pub_from_enc)
    print("\nthe result of signature from C:\n", res_sig_c)
    
    p2pk = False

    for i in range(len(tx_split["ins"])):
        
        ecdsa_tx_sign_out = der_encode_sig(*rawsig)+encode(SIGHASH_ALL & 255, 16, 2)
        
        script = serialize_script([ecdsa_tx_sign_out]) if p2pk else serialize_script([ecdsa_tx_sign_out, pub_from_enc])
        tx_split["ins"][i]["script"] = script
        if "witness" in tx_split.keys():
            witness: Witness = {"number": 0, "scriptCode": ''}
            # Pycharm IDE gives a type error for the following line, no idea why...
            # noinspection PyTypeChecker
            tx_split["witness"].append(witness)
    print("\nSigned ransaction after splitting steps:\n", tx_split)

    tx_split_ser = serialize(tx_split)
    print("\nRaw signed transaction:\n" + tx_split_ser)
    txid = c.pushtx(tx_split_ser)
    print("\nTxid:" + txid)

if __name__ == "__main__":
    main()