from cryptos import *

def main():
    c = Litecoin(testnet=True)
    x_coord = int("11FE116B04F1A4A078436B92C1092008F567C3F2E4855332569D822D2813521E", 16)
    y_coord = int("9D1AE95967F7B1C7A24E8E888E756ABE57A395FE49225AA21DE0A71D4C259C0B", 16)
    
    joint_pk = (x_coord, y_coord)

    pub_from_enc = encode_pubkey(joint_pk, "hex_compressed")
    print("\nEncoded Public Key in hex:\n", pub_from_enc)

    addr = c.pubtoaddr(pub_from_enc)
    print("\nMy address:\n" + addr)    

if __name__ == "__main__":
    main()