from cryptos import *

def main():
    c = Litecoin(testnet=True)
    
    priv = "***"

    inputs = c.unspent('tltc1q963x0ukhel2qpug49tv6gl2gz79ztusxqyrjn5')
    
    outputs = [{'value': 7430000, 'address': 'mzuA3ArQC7eEbELjpajyUL6VUttgN9bo4i'},{'value': 0, 'address': 'QYXkAfpofUDgwyK78pTYEevncTa1NJM4Js'}]
    
    tx = c.mktx(inputs,outputs)
    print("\nUnsigned ransaction:\n", tx)
    
    tx2 = c.signall(tx, priv)
    print("\nSigned ransaction:\n", tx2)
    
    tx3 = serialize(tx2)
   
    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx3)
    txid = c.pushtx(tx3)
    print("\nTxid:" + txid)


if __name__ == "__main__":
    main()