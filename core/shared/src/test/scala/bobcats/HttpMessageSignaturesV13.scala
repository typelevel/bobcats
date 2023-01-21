/*
 * Copyright 2021 Typelevel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bobcats

import bobcats.SignatureExample.{Base64Bytes, PublicKeyPEM}
import util.StringUtils.StringW

/**
 * Examples taken from Signing HTTP Messages RFC draft 13
 *
 * @see
 *   https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures
 */
object HttpMessageSignaturesV13 extends AsymmetricKeyExamples with SymmetricKeyExamples {

  import SignatureExample.PrivateKeyPEM

  override def symSignExamples: Seq[SymmetricSignatureExample] = Seq(
    `Appendix_B.2.5`
  )

  def sigExamples: Seq[SignatureExample] = Seq(
    `§2.4_Example`,
    `§2.5_Example`,
    `§4.3_Multiple_Signatures`,
    `Appendix_B.2.2`,
    `Appendix_B.2.3`,
    `Appendix_B.2.4`,
    `Appendix_B.2.6`,
    `Appendix_B.3`,
    `Appendix_B.4`
  )

  object `§2.4_Example`
      extends SignatureExample(
        description = "Request-Response Signature Binding",
        sigtext = """\
       |"@status": 503
       |"content-length": 62
       |"content-type": application/json
       |"signature";req;key="sig1": :LAH8BjcfcOcLojiuOBFWn0P5keD3xAOuJRGziC\
       |  LuD8r5MW9S0RoXXLzLSRfGY/3SF8kVIkHjE13SEFdTo4Af/fJ/Pu9wheqoLVdwXyY\
       |  /UkBIS1M8Brc8IODsn5DFIrG0IrburbLi0uCc+E2ZIIb6HbUJ+o+jP58JelMTe0QE\
       |  3IpWINTEzpxjqDf5/Df+InHCAkQCTuKsamjWXUpyOT1Wkxi7YPVNOjW4MfNuTZ9Hd\
       |  bD2Tr65+BXeTG9ZS/9SWuXAc+BZ8WyPz0QRz//ec3uWXd7bYYODSjRAxHqX+S1ag3\
       |  LZElYyUKaAIjZ8MGOt4gXEwCSLDv/zqxZeWLj/PDkn6w==:
       |"@authority";req: example.com
       |"@method";req: POST
       |"@signature-params": ("@status" "content-length" "content-type" \
       |  "signature";req;key="sig1" "@authority";req "@method";req)\
       |  ;created=1618884479;keyid="test-key-ecc-p256"""".rfc8792single,
        signature = """mh17P4TbYYBmBwsXPT4nsyVzW4Rp9Fb8WcvnfqKCQLoMvzOB\
          LD/n32tL/GPW6XE5GAS5bdsg1khK6lBzV1Cx/Q==""".rfc8792single,
        keypair = `test-key-ecc-p256`,
        signatureAlg = AsymmetricKeyAlg.`ecdsa-p256-sha256` // ? is this correct?
      )

  object `§2.5_Example`
      extends SignatureExample(
        description = "Example from §2.5 signed in §3.1",
        sigtext = """\
      |"@method": POST
      |"@authority": example.com
      |"@path": /foo
      |"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX\
      |  +TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
      |"content-length": 18
      |"content-type": application/json
      |"@signature-params": ("@method" "@authority" "@path" \
      |  "content-digest" "content-length" "content-type")\
      |  ;created=1618884473;keyid="test-key-rsa-pss"""".rfc8792single,
        signature = """HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2\
       YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ\
       +xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1Uz\
       VVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBc\
       E9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6H\
       RalVc/g==""".rfc8792single,
        keypair = `test-key-rsa-pss`,
        signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
      )
      
  object `§4.3_Multiple_Signatures` extends SignatureExample(
    description = "4.3 multiple signatures example",
    sigtext = """\
       |"signature";key="sig1": :hNojB+wWw4A7SYF3qK1S01Y4UP5i2JZFYa2WOlMB4N\
       |  p5iWmJSO0bDe2hrYRbcIWqVAFjuuCBRsB7lYQJkzbb6g==:
       |"@authority": origin.host.internal.example
       |"forwarded": for=192.0.2.123
       |"@signature-params": ("signature";key="sig1" "@authority" \
       |  "forwarded");created=1618884480;keyid="test-key-rsa"\
       |  ;alg="rsa-v1_5-sha256";expires=1618884540""".rfc8792single,
    signature = """\
       YvYVO11F+Q+N4WZNeBdjFKluswwE3vQ4cTXpBwEiMz2hwu0J+wSJLRhHlIZ1N83epfn\
       KDxY9cbNaVlbtr2UOLkw5O5Q5M5yrjx3s1mgDOsV7fuItD6iDyNISCiKRuevl+M+TyY\
       Bo10ubG83As5CeeoUdmrtI4G6QX7RqEeX0Xj/CYofHljr/dVzARxskjHEQbTztYVg4W\
       D+LWo1zjx9w5fw26tsOMagfXLpDb4zb4/lgpgyNKoXFwG7c89KId5q+0BC+kryWuA35\
       ZcQGaRPAz/NqzeKq/c7p7b/fmHS71fy1jOaFgWFmD+Z77bJLO8AVKuF0y2fpL3KUYHy\
       ITQHOsA==""".rfc8792single,
    keypair = `test-key-rsa`,
    signatureAlg = AsymmetricKeyAlg.`rsa-v1_5-sha256`
  )

  object `Appendix_B.2.2`
      extends SignatureExample(
        description = "Selective Covered Components using rsa-pss-sha512",
        sigtext = """\
        |"@authority": example.com
        |"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX\
        |  +TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
        |"@query-param";name="Pet": dog
        |"@signature-params": ("@authority" "content-digest" \
        |  "@query-param";name="Pet")\
        |  ;created=1618884473;keyid="test-key-rsa-pss"\
        |  ;tag="header-example"""".rfc8792single,
        signature = """LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ\
         EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT\
         8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA\
         RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd\
         4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK\
         UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==""".rfc8792single,
        keypair = `test-key-rsa-pss`,
        signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
      )

  object `Appendix_B.2.3`
      extends SignatureExample(
        description = "Full Coverage using rsa-pss-sha512",
        sigtext = """\
      |"date": Tue, 20 Apr 2021 02:07:55 GMT
      |"@method": POST
      |"@path": /foo
      |"@query": ?param=Value&Pet=dog
      |"@authority": example.com
      |"content-type": application/json
      |"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX\
      |  +TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
      |"content-length": 18
      |"@signature-params": ("date" "@method" "@path" "@query" \
      |  "@authority" "content-type" "content-digest" "content-length")\
      |  ;created=1618884473;keyid="test-key-rsa-pss"""".rfc8792single,
        signature = """bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB\
         iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU\
         xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1\
         pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9\
         bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z\
         JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==""".rfc8792single,
        keypair = `test-key-rsa-pss`,
        signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
      )

  object `Appendix_B.2.4`
      extends SignatureExample(
        description = "Signing a Response using ecdsa-p256-sha256",
        sigtext =
          """\
           |"@status": 200
           |"content-type": application/json
           |"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ4\
           |  1QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
           |"content-length": 23
           |"@signature-params": ("@status" "content-type" "content-digest" \
           |  "content-length");created=1618884473;keyid="test-key-ecc-p256"""".rfc8792single,
        signature = """wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NK\
           ocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==""".rfc8792single,
        keypair = `test-key-ecc-p256`,
        signatureAlg = AsymmetricKeyAlg.`ecdsa-p256-sha256`)

  object `Appendix_B.2.5`
      extends SymmetricSignatureExample(
        description = "Appendix B.2.5 Signing a Request using symmetric key hmac-sha256",
        sigtext = """\
        |"date": Tue, 20 Apr 2021 02:07:55 GMT
        |"@authority": example.com
        |"content-type": application/json
        |"@signature-params": ("date" "@authority" "content-type")\
        |  ;created=1618884473;keyid="test-shared-secret"""".rfc8792single,
        signature = """pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=""",
        key = `test-shared-secret`,
        signatureAlg = HmacAlgorithm.SHA256)

  object `Appendix_B.2.6`
      extends SignatureExample(
        description = "Appendix B.2.6 Signing a Request using ed25519",
        sigtext = """\
       |"date": Tue, 20 Apr 2021 02:07:55 GMT
       |"@method": POST
       |"@path": /foo
       |"@authority": example.com
       |"content-type": application/json
       |"content-length": 18
       |"@signature-params": ("date" "@method" "@path" "@authority" \
       |  "content-type" "content-length");created=1618884473\
       |  ;keyid="test-key-ed25519"""".rfc8792single,
        signature = """wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1\
         u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==""".rfc8792single,
        keypair = `test-key-ed25519`,
        signatureAlg = AsymmetricKeyAlg.`ed25119`,
        valid = true)

  object `Appendix_B.3`
      extends SignatureExample(
        description = "Appendix B.3: TLS-Terminating Example",
        sigtext =
          """\
       |"@path": /foo
       |"@query": ?param=Value&Pet=dog
       |"@method": POST
       |"@authority": service.internal.example
       |"client-cert": :MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQ\
       |  KDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBD\
       |  QTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDM\
       |  FkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXm\
       |  ckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQY\
       |  DVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8B\
       |  Af8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQ\
       |  GV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0\
       |  Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:
       |"@signature-params": ("@path" "@query" "@method" "@authority" \
       |  "client-cert");created=1618884473;keyid="test-key-ecc-p256"""".rfc8792single,
        signature = """xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0y\
       zhD9ah4JHRwMLOgmizw==""".rfc8792single,
        keypair = `test-key-ecc-p256`,
        signatureAlg = AsymmetricKeyAlg.`ecdsa-p256-sha256`,
        valid = true)

  object `Appendix_B.4`
      extends SignatureExample(
        description = "Appendix B.4 Http Message Transforamation",
        sigtext = """\
            |"@method": GET
            |"@path": /demo
            |"@authority": example.org
            |"accept": application/json, */*
            |"@signature-params": ("@method" "@path" "@authority" "accept")\
            |  ;created=1618884473;keyid="test-key-ed25519"""".rfc8792single,
        signature = """ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5J\
         Z1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==""".rfc8792single,
        keypair = `test-key-ed25519`,
        signatureAlg = AsymmetricKeyAlg.`ed25119`,
        valid = true)

  // thanks to sjrd for this tip
  def isJS: Boolean = 1.0.toString() == "1"

  // It turned out all the keys from this version were the same as 07
  // The only tricky one was test-key-rsa-pss which was the same key
  // in a different encoding.

  /**
   * 2048-bit RSA public and private key pair, given in
   * https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html#appendix-B.1.1
   * this key did not change note: the private key needed to be updated to pkcs8
   */
  val `test-key-rsa` = HttpMessageSignaturesV07.`test-key-rsa`

  /**
   * 2048-bit RSA public and private key pair taken from
   * [[https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#appendix-B.1.2 draft 13 Appendix B.1.2]]
   * [[https://github.com/w3c/webcrypto/issues/330#issuecomment-1304759709 wrote on the webcrypto https://github.com/w3c/webcrypto/issues/330#issuecomment-1304759709]]
   * issue: "The private key in appendix-B.1.2 is 1.2.840.113549.1.1.10 (id-RSASSA-PSS).
   * WebCryptoAPI implementations only generally accept 1.2.840.113549.1.1.1 (rsaEncryption)
   * keys. Recommend using rsaEncryption OID PKCS8 PEM or JWK if they ought to be imported as
   * CryptoKey reliably."
   */
  def `test-key-rsa-pss` = if (isJS)
    HttpMessageSignaturesV07.`test-key-rsa-pss`
  else {
    // these are the new keys, but they can't be loaded into Web Crypto API
    // https://github.com/httpwg/http-extensions/issues/2290
    new TestKeyPair {
      override def description: String = "test-key-rsa-pss"

      override def privateKey: PrivateKeyPEM =
        """-----BEGIN PRIVATE KEY-----
          |MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
          |P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
          |3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
          |FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
          |AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
          |9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
          |c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
          |pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
          |aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
          |XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
          |HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
          |2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
          |RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
          |DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
          |vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
          |rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
          |4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
          |FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
          |OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
          |NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
          |NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
          |3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
          |t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
          |dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
          |S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
          |rOjr9w349JooGXhOxbu8nOxX
          |-----END PRIVATE KEY-----""".stripMargin

      override def publicKey: PublicKeyPEM =
        """-----BEGIN PUBLIC KEY-----
          |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
          |+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
          |oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
          |gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
          |Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
          |aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
          |2wIDAQAB
          |-----END PUBLIC KEY-----"""".stripMargin

      override def privateJwkKey: Map[String, String] =
        HttpMessageSignaturesV07.`test-key-rsa-pss`.privateJwkKey

      override def keyAlg: AsymmetricKeyAlg = AsymmetricKeyAlg.RSA_PSS_Key
    }
  }

  /**
   * Taken from
   * [[https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#appendix-B.1.3 draft 13 Appendix B.1.3]]
   * But as panva tells us on
   * [[https://github.com/w3c/webcrypto/issues/330#issuecomment-1304759709 issue 330 of webcrypto]]:
   * "The private key in appendix-B.1.3 is in SEC1 format, which isn't accepted by webcrypto at
   * all. Recommend using id-ecPublicKey OID PKCS8 PEM or JWK if they ought to be imported as
   * CryptoKey reliably." We somehow managed to update the key to the correct version in v07.
   */
  val `test-key-ecc-p256`: TestKeyPair = HttpMessageSignaturesV07.`test-key-ecc-p256`

  /**
   * Taken from
   * [[https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#appendix-B.1.3 draft 13 Appendix B.1.4]]
   * This did not change from draft 7
   */
  val `test-key-ed25519`: TestKeyPair = HttpMessageSignaturesV07.`test-key-ed25519`

  /**
   * Symmetric key from Appendix B.1.5
   */
  object `test-shared-secret` extends TestSharedKey {
    override def sharedKey: Base64Bytes =
      """uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBt
        |bmHhIDi6pcl8jsasjlTMtDQ==""".stripMargin

    override def description: PrivateKeyPEM = "test-shared-secret"
  }

}
