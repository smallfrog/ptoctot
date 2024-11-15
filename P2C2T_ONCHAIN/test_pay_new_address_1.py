from cryptos import *

def main():
    c = Bitcoin(testnet=True)
    
    priv = "***"

    inputs = c.unspent('mgnRdzyRYH9eyaYbV89u5QP4f8WgQgWM6S')

    outputs = [{'value': 15000, 'address': 'n2XSUne7GUnj6Fy4wNQMJiNLaLE4pGRQs4'}, {'value': 0, 'address': '2MzKf17jzLf9HntXWE5LJw5neWAJysTi8xU'}]
   
    tx = c.mktx(inputs, outputs)
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