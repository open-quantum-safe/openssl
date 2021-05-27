| Family         | Implementation Version   | Variant         |   Claimed NIST Level | PQ-only Code Point   | Hybrid Elliptic Curve   | Hybrid Code Point   |
|:---------------|:-------------------------|:----------------|---------------------:|:---------------------|:------------------------|:--------------------|
| BIKE           | 3.2                      | bike1l1cpa      |                    1 | 0x0206               | secp256_r1              | 0x2F06              |
| BIKE           | 3.2                      | bike1l3cpa      |                    3 | 0x0207               | secp384_r1              | 0x2F07              |
| BIKE           | 3.2                      | bike1l1fo       |                    1 | 0x0223               | x25519                  | 0x2F28              |
| BIKE           | 3.2                      | bike1l1fo       |                    1 | 0x0223               | secp256_r1              | 0x2F23              |
| BIKE           | 3.2                      | bike1l3fo       |                    3 | 0x0224               | secp384_r1              | 0x2F24              |
| CRYSTALS-Kyber | NIST submission: R2      | kyber512        |                    1 | 0x020F               | x25519                  | 0x2F26              |
| CRYSTALS-Kyber | NIST submission: R2      | kyber512        |                    1 | 0x020F               | secp256_r1              | 0x2F0F              |
| CRYSTALS-Kyber | NIST submission: R2      | kyber768        |                    3 | 0x0210               | secp384_r1              | 0x2F10              |
| CRYSTALS-Kyber | NIST submission: R2      | kyber1024       |                    5 | 0x0211               | secp521_r1              | 0x2F11              |
| CRYSTALS-Kyber | NIST submission: R2      | kyber90s512     |                    1 | 0x0229               | secp256_r1              | 0x2F29              |
| CRYSTALS-Kyber | NIST submission: R2      | kyber90s768     |                    3 | 0x022A               | secp384_r1              | 0x2F2A              |
| CRYSTALS-Kyber | NIST submission: R2      | kyber90s1024    |                    5 | 0x022B               | secp521_r1              | 0x2F2B              |
| FrodoKEM       | NIST submission: R2, R3  | frodo640aes     |                    1 | 0x0200               | secp256_r1              | 0x2F00              |
| FrodoKEM       | NIST submission: R2, R3  | frodo640shake   |                    1 | 0x0201               | secp256_r1              | 0x2F01              |
| FrodoKEM       | NIST submission: R2, R3  | frodo976aes     |                    3 | 0x0202               | secp384_r1              | 0x2F02              |
| FrodoKEM       | NIST submission: R2, R3  | frodo976shake   |                    3 | 0x0203               | secp384_r1              | 0x2F03              |
| FrodoKEM       | NIST submission: R2, R3  | frodo1344aes    |                    5 | 0x0204               | secp521_r1              | 0x2F04              |
| FrodoKEM       | NIST submission: R2, R3  | frodo1344shake  |                    5 | 0x0205               | secp521_r1              | 0x2F05              |
| HQC            | 2020/10/01               | hqc128          |                    1 | 0x022C               | secp256_r1              | 0x2F2C              |
| HQC            | 2020/10/01               | hqc192          |                    3 | 0x022D               | secp384_r1              | 0x2F2D              |
| HQC            | 2020/10/01               | hqc256          |                    5 | 0x022E               | secp521_r1              | 0x2F2E              |
| NTRU           | NIST submission: R2, R3  | ntru_hps2048509 |                    1 | 0x0214               | secp256_r1              | 0x2F14              |
| NTRU           | NIST submission: R2, R3  | ntru_hps2048677 |                    3 | 0x0215               | secp384_r1              | 0x2F15              |
| NTRU           | NIST submission: R2, R3  | ntru_hps4096821 |                    5 | 0x0216               | secp521_r1              | 0x2F16              |
| NTRU           | NIST submission: R2, R3  | ntru_hrss701    |                    3 | 0x0217               | secp384_r1              | 0x2F17              |
| NTRU-Prime     | supercop-20200826        | ntrulpr653      |                    1 | 0x022F               | secp256_r1              | 0x2F2F              |
| NTRU-Prime     | supercop-20200826        | ntrulpr761      |                    3 | 0x0230               | secp384_r1              | 0x2F30              |
| NTRU-Prime     | supercop-20200826        | ntrulpr857      |                    3 | 0x0231               | secp384_r1              | 0x2F31              |
| NTRU-Prime     | supercop-20200826        | sntrup653       |                    1 | 0x0232               | secp256_r1              | 0x2F32              |
| NTRU-Prime     | supercop-20200826        | sntrup761       |                    3 | 0x0233               | secp384_r1              | 0x2F33              |
| NTRU-Prime     | supercop-20200826        | sntrup857       |                    3 | 0x0234               | secp384_r1              | 0x2F34              |
| SABER          | NIST submission: R2, R3  | lightsaber      |                    1 | 0x0218               | secp256_r1              | 0x2F18              |
| SABER          | NIST submission: R2, R3  | saber           |                    3 | 0x0219               | secp384_r1              | 0x2F19              |
| SABER          | NIST submission: R2, R3  | firesaber       |                    5 | 0x021A               | secp521_r1              | 0x2F1A              |
| SIDH           | 3.3                      | sidhp434        |                    1 | 0x021B               | secp256_r1              | 0x2F1B              |
| SIDH           | 3.3                      | sidhp503        |                    1 | 0x021C               | secp256_r1              | 0x2F1C              |
| SIDH           | 3.3                      | sidhp610        |                    3 | 0x021D               | secp384_r1              | 0x2F1D              |
| SIDH           | 3.3                      | sidhp751        |                    5 | 0x021E               | secp521_r1              | 0x2F1E              |
| SIKE           | NIST submission: R2, R3  | sikep434        |                    1 | 0x021F               | x25519                  | 0x2F27              |
| SIKE           | NIST submission: R2, R3  | sikep434        |                    1 | 0x021F               | secp256_r1              | 0x2F1F              |
| SIKE           | NIST submission: R2, R3  | sikep503        |                    1 | 0x0220               | secp256_r1              | 0x2F20              |
| SIKE           | NIST submission: R2, R3  | sikep610        |                    3 | 0x0221               | secp384_r1              | 0x2F21              |
| SIKE           | NIST submission: R2, R3  | sikep751        |                    5 | 0x0222               | secp521_r1              | 0x2F22              |
