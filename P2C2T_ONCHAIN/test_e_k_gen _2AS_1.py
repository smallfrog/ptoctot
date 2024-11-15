from cryptos import *

def main():

    c = Bitcoin(testnet=True)

    x_coord = int("6956DD097BBABD4308299B2B6573D4E17C661BB43E70B9B252E8C97A87536EA4", 16)
    y_coord = int("D14D51C7C56388C65237594005FDB6232AA1095F94B544928E16146815B72509", 16)
    
    joint_pk = (x_coord, y_coord)

    pub_from_enc = encode_pubkey(joint_pk, "hex_compressed")

    inputs = c.unspent("msjYibdB4v6SqyA4xjNPzwm7F21GcJn5jB")
    print("\nFrom inputs:\n", inputs)
 
    outs = [{'value': 10000, 'address': 'mqVqVsMaqsSuLUMjhSgjMykhtEMNMmAzvh'}]
    
    tx = c.mktx(inputs,outs)
    print("\nUnsigned transaction:\n", tx)    
    tx_split = tx

    script = addr_to_pubkey_script("msjYibdB4v6SqyA4xjNPzwm7F21GcJn5jB")
    tx4 = signature_form(tx_split, 0, script, SIGHASH_ALL)    
    print("\nSigning transaction:\n", tx4)

    bin_txh = bin_txhash(tx4, SIGHASH_ALL)
    print("\nbin of txhash connecting with hashcode 1:\n", bin_txh)
    e = hash_to_int(bin_txh)
    print("\nint of txhash connecting with hashcode 1:\n", e)

    priv_s = "***"
    k_s = deterministic_generate_k(tx4, priv_s)
    print("\nk_s value:\n", k_s)

    priv_h1 = "***"
    k_h1 = deterministic_generate_k(tx4, priv_h1)
    print("\nk_h1 value:\n", k_h1)

    
    v = 32
    r = int("A92FE9AA807DB32B5022D9F60B4B638FD89E23801D8D61999BD3892C91BF1B1C",16)
    s = int("10E5520E893B16914B5F5DC71DC73CEE53E5B1779979FC3FAA7A4717433D9F68",16)
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