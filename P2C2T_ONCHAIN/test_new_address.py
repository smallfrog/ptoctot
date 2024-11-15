from cryptos import *

def main():
    c = Bitcoin(testnet=True)

    x_coord = int("7020D7AEFFBF0B9DBA065465204792CA6579F11AD80773CD4169872EE7C1453B", 16)
    y_coord = int("0B8C8FDF5DFDA9061F9A80243B559AD9BD12A8E27063800193A54957D68338CD", 16)
    
    joint_pk = (x_coord, y_coord)

    pub_from_enc = encode_pubkey(joint_pk, "hex_compressed")
    print("\nEncoded Public Key in hex:\n", pub_from_enc)

    addr = c.pubtoaddr(pub_from_enc)
    print("\nMy address:\n" + addr)

if __name__ == "__main__":
    main()