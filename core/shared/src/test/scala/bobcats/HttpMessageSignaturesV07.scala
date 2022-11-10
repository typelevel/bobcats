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

import bobcats.util.StringUtils.StringW
import bobcats.SignatureExample._

/**
 * Examples taken from Signing HTTP Messages RFC draft
 *
 * @see
 *   https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html
 */
object HttpMessageSignaturesV07 extends AsymmetricKeyExamples {

  def sigExamples: Seq[SignatureExample] = Seq(
    `§2.2.11_Example`,
    `§3.1_Signature`,
    `§4.3_Example`,
    `Appendix_B.2.1`,
    `Appendix_B.2.2`,
    `Appendix_B.2.3`,
    `Appendix_B.2.4`,
    `Github-Issue-1509-Example`
  )

  object `§2.2.11_Example`
      extends SignatureExample(
        description = "§2.2.11 Request-Response Example",
        sigtext = """"content-type": application/json
			 |"content-length": 62
			 |"@status": 200
			 |"@request-response";key="sig1": :KuhJjsOKCiISnKHh2rln5ZNIrkRvue0DSu\
			 |  5rif3g7ckTbbX7C4Jp3bcGmi8zZsFRURSQTcjbHdJtN8ZXlRptLOPGHkUa/3Qov79\
			 |  gBeqvHNUO4bhI27p4WzD1bJDG9+6ml3gkrs7rOvMtROObPuc78A95fa4+skS/t2T7\
			 |  OjkfsHAm/enxf1fAwkk15xj0n6kmriwZfgUlOqyff0XLwuH4XFvZ+ZTyxYNoo2+Ef\
			 |  Fg4NVfqtSJch2WDY7n/qmhZOzMfyHlggWYFnDpyP27VrzQCQg8rM1Crp6MrwGLa94\
			 |  v6qP8pq0sQVq2DLt4NJSoRRqXTvqlWIRnexmcKXjQFVz6YSA==:
			 |"@signature-params": ("content-type" "content-length" "@status" \
			 |  "@request-response";key="sig1");created=1618884475\
			 |  ;keyid="test-key-ecc-p256"""".rfc8792single,
        signature = """crVqK54rxvdx0j7qnt2RL1oQSf+o21S/6Uk2hyFpoIfOT0q+Hv\
		  |  msYAXUXzo0Wn8NFWh/OjWQOXHAQdVnTk87Pw==""".rfc8792single,
        keypair = `test-key-ecc-p256`,
        signatureAlg = AsymmetricKeyAlg.`ecdsa-p256-sha256` // ? is this correct?
      )

  object `§3.1_Signature`
      extends SignatureExample(
        description = "§3.1_Signature example",
        sigtext = // defined https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html#section-2.3
          """"@method": GET
            |"@path": /foo
            |"@authority": example.org
            |"cache-control": max-age=60, must-revalidate
            |"x-empty-header": \
            |
            |"x-example": Example header with some whitespace.
            |"@signature-params": ("@method" "@path" "@authority" \
            |  "cache-control" "x-empty-header" "x-example");created=1618884475\
            |  ;keyid="test-key-rsa-pss"""".rfc8792single,
        signature = """P0wLUszWQjoi54udOtydf9IWTfNhy+r53jGFj9XZuP4uKwxyJo1RSHi+oEF1FuX6O29\
			  |d+lbxwwBao1BAgadijW+7O/PyezlTnqAOVPWx9GlyntiCiHzC87qmSQjvu1CFyFuWSj\
			  |dGa3qLYYlNm7pVaJFalQiKWnUaqfT4LyttaXyoyZW84jS8gyarxAiWI97mPXU+OVM64\
			  |+HVBHmnEsS+lTeIsEQo36T3NFf2CujWARPQg53r58RmpZ+J9eKR2CD6IJQvacn5A4Ix\
			  |5BUAVGqlyp8JYm+S/CWJi31PNUjRRCusCVRj05NrxABNFv3r5S9IXf2fYJK+eyW4AiG\
			  |VMvMcOg==""".rfc8792single,
        keypair = `test-key-rsa-pss`,
        signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
      )

  object `§4.3_Example`
      extends SignatureExample(
        description = "§4.3 Example",
        sigtext =
          """"signature";key="sig1": :P0wLUszWQjoi54udOtydf9IWTfNhy+r53jGFj9XZuP\
            |  4uKwxyJo1RSHi+oEF1FuX6O29d+lbxwwBao1BAgadijW+7O/PyezlTnqAOVPWx9Gl\
            |  yntiCiHzC87qmSQjvu1CFyFuWSjdGa3qLYYlNm7pVaJFalQiKWnUaqfT4LyttaXyo\
            |  yZW84jS8gyarxAiWI97mPXU+OVM64+HVBHmnEsS+lTeIsEQo36T3NFf2CujWARPQg\
            |  53r58RmpZ+J9eKR2CD6IJQvacn5A4Ix5BUAVGqlyp8JYm+S/CWJi31PNUjRRCusCV\
            |  Rj05NrxABNFv3r5S9IXf2fYJK+eyW4AiGVMvMcOg==:
            |"forwarded": for=192.0.2.123
            |"@signature-params": ("signature";key="sig1" "forwarded")\
            |  ;created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256"""".rfc8792single,
        signature = """cjGvZwbsq9JwexP9TIvdLiivxqLINwp/ybAc19KOSQuLvtmMt3EnZxNiE+797dXK2cj\
            |PPUFqoZxO8WWx1SnKhAU9SiXBr99NTXRmA1qGBjqus/1Yxwr8keB8xzFt4inv3J3zP0\
            |k6TlLkRJstkVnNjuhRIUA/ZQCo8jDYAl4zWJJjppy6Gd1XSg03iUa0sju1yj6rcKbMA\
            |BBuzhUz4G0u1hZkIGbQprCnk/FOsqZHpwaWvY8P3hmcDHkNaavcokmq+3EBDCQTzgwL\
            |qfDmV0vLCXtDda6CNO2Zyum/pMGboCnQn/VkQ+j8kSydKoFg6EbVuGbrQijth6I0dDX\
            |2/HYcJg==""".rfc8792single,
        keypair = `test-key-rsa`,
        signatureAlg = AsymmetricKeyAlg.`rsa-v1_5-sha256`
      )

  object `Appendix_B.2.1`
      extends SignatureExample(
        description = "Appendix_B.2.1 minimal example",
        sigtext = """"@signature-params": ();created=1618884475\
			  |  ;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"""".rfc8792single,
        signature = """HWP69ZNiom9Obu1KIdqPPcu/C1a5ZUMBbqS/xwJECV8bhIQVmE\
			  |AAAzz8LQPvtP1iFSxxluDO1KE9b8L+O64LEOvhwYdDctV5+E39Jy1eJiD7nYREBgx\
			  |TpdUfzTO+Trath0vZdTylFlxK4H3l3s/cuFhnOCxmFYgEa+cw+StBRgY1JtafSFwN\
			  |cZgLxVwialuH5VnqJS4JN8PHD91XLfkjMscTo4jmVMpFd3iLVe0hqVFl7MDt6TMkw\
			  |IyVFnEZ7B/VIQofdShO+C/7MuupCSLVjQz5xA+Zs6Hw+W9ESD/6BuGs6LF1TcKLxW\
			  |+5K+2zvDY/Cia34HNpRW5io7Iv9/b7iQ==""".rfc8792single,
        keypair = `test-key-rsa-pss`,
        signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
      )

  object `Appendix_B.2.2`
      extends SignatureExample(
        description = "Appendix_B.2.2 selective header example",
        sigtext = """"@authority": example.com
			  |"content-type": application/json
			  |"@signature-params": ("@authority" "content-type")\
			  |  ;created=1618884475;keyid="test-key-rsa-pss"""".rfc8792single,
        signature = """ik+OtGmM/kFqENDf9Plm8AmPtqtC7C9a+zYSaxr58b/E6h81gh\
			  |  JS3PcH+m1asiMp8yvccnO/RfaexnqanVB3C72WRNZN7skPTJmUVmoIeqZncdP2mlf\
			  |  xlLP6UbkrgYsk91NS6nwkKC6RRgLhBFqzP42oq8D2336OiQPDAo/04SxZt4Wx9nDG\
			  |  uy2SfZJUhsJqZyEWRk4204x7YEB3VxDAAlVgGt8ewilWbIKKTOKp3ymUeQIwptqYw\
			  |  v0l8mN404PPzRBTpB7+HpClyK4CNp+SVv46+6sHMfJU4taz10s/NoYRmYCGXyadzY\
			  |  YDj0BYnFdERB6NblI/AOWFGl5Axhhmjg==""".rfc8792single,
        keypair = `test-key-rsa-pss`,
        signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
      )

  object `Appendix_B.2.3`
      extends SignatureExample(
        description = "Appendix_B.2.3 full coverage example",
        sigtext = """"date": Tue, 20 Apr 2021 02:07:56 GMT
			  |"@method": POST
			  |"@path": /foo
			  |"@query": ?param=value&pet=dog
			  |"@authority": example.com
			  |"content-type": application/json
			  |"digest": SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
			  |"content-length": 18
			  |"@signature-params": ("date" "@method" "@path" "@query" \
			  |  "@authority" "content-type" "digest" "content-length")\
			  |  ;created=1618884475;keyid="test-key-rsa-pss"""".rfc8792single,
        signature = """JuJnJMFGD4HMysAGsfOY6N5ZTZUknsQUdClNG51VezDgPUOW03\
			  |  QMe74vbIdndKwW1BBrHOHR3NzKGYZJ7X3ur23FMCdANe4VmKb3Rc1Q/5YxOO8p7Ko\
			  |  yfVa4uUcMk5jB9KAn1M1MbgBnqwZkRWsbv8ocCqrnD85Kavr73lx51k1/gU8w673W\
			  |  T/oBtxPtAn1eFjUyIKyA+XD7kYph82I+ahvm0pSgDPagu917SlqUjeaQaNnlZzO03\
			  |  Iy1RZ5XpgbNeDLCqSLuZFVID80EohC2CQ1cL5svjslrlCNstd2JCLmhjL7xV3NYXe\
			  |  rLim4bqUQGRgDwNJRnqobpS6C1NBns/Q==""".rfc8792single,
        keypair = `test-key-rsa-pss`,
        signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
      )

  object `Appendix_B.2.4`
      extends SignatureExample(
        description = "Appendix_B.2.4 Elliptic Curve example",
        sigtext = """"content-type": application/json
			  |"digest": SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
			  |"content-length": 18
			  |"@signature-params": ("content-type" "digest" "content-length")\
			  |  ;created=1618884475;keyid="test-key-ecc-p256"""".rfc8792single,
        signature = """n8RKXkj0iseWDmC6PNSQ1GX2R9650v+lhbb6rTGoSrSSx18zmn\
			  |  6fPOtBx48/WffYLO0n1RHHf9scvNGAgGq52Q==""".rfc8792single,
        keypair = `test-key-ecc-p256`,
        signatureAlg = AsymmetricKeyAlg.`ecdsa-p256-sha256`
      )

  object `Github-Issue-1509-Example`
      extends SignatureExample(
        description =
          "Add Ed25519 support https://github.com/httpwg/http-extensions/issues/1509",
        sigtext = """"date": Tue, 20 Apr 2021 02:07:56 GMT
                    |"@method": POST
                    |"@path": /foo
                    |"@authority": example.com
                    |"content-type": application/json
                    |"content-length": 18
                    |"@signature-params": ("date" "@method" "@path" "@authority" \
                    |  "content-type" "content-length");created=1618884475\
                    |  ;keyid="test-key-ed25519"""".rfc8792single,
        signature = """u9DvOJe17NdTTuIJjKac9WncuAo/1d4gOh6TXMV6AN4hxLdttB\
                      |  SegWS/RcWPZ+lENCtykh6YGl8GJiQrxgibBg==""".rfc8792single,
        keypair = `test-key-ed25519`,
        signatureAlg = bobcats.AsymmetricKeyAlg.ed25119
      )

  // 2048-bit RSA public and private key pair,
  // given in https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html#appendix-B.1.1
  object `test-key-rsa` extends TestKeyPair {
    override def description: String = "test-key-rsa"

    override def privateKey: PrivateKeyPEM =
      """-----BEGIN RSA PRIVATE KEY-----
        |MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
        |BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
        |JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
        |jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
        |lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
        |SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
        |vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
        |CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
        |+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
        |yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
        |Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
        |YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
        |cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
        |DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
        |mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
        |qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
        |B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
        |9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
        |f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
        |81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
        |/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
        |IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
        |qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
        |WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
        |EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
        |-----END RSA PRIVATE KEY-----""".stripMargin

    override def privatePk8Key: PrivateKeyPEM =
      """-----BEGIN PRIVATE KEY-----
        |MIIEwgIBADANBgkqhkiG9w0BAQEFAASCBKwwggSoAgEAAoIBAQCEAph22h6jLzNw
        |BxHzvgvxydnErMAbB3u/foA+ns+/pDaN2w8FGvBYQGd7Pp3RQMoPAZtzqfF8RcDL
        |mZuGBqPOvDcw4S3y4Dm3FIqhsGkoN4Es6x0koWowaZcJC8Qbth6ZzENNE/ECV4gC
        |BhhGNNJ39AHBVb07A0WF6SujdG2WKdXRrvmN9mCSd79iKS1K8sbfiXDbOpcENMLk
        |0dE5SoZOUwvg+U1lLlGLZThoI3HatQ9FwoiUTQ+4rEjhP4choWm/z6t1Xp5SA6sH
        |bF4jV1IUWf+ee/k6hkkQgH5Wa4qfcMJRwJlIWVA9JdJ8EOJQaHA7Dvpa5JKx/UPh
        |v+8ugnXTAgMBAAECggEAb8lm5JZ2hUduLnq+OAKCSODeWQ7Uqs7eet2bqeuAD0/2
        |po+PG4qhZoo7VwFCUTWlJan9wqdxiAPlbEQKkCdFRcbakbjN2TMJjMCHWL5zfgvq
        |hmgeyKsrqg1wSce97J1/Mkvn3fh6CbqnwNb6bVFDvTJS3i5FzRhKiv6rUsYm8ZAd
        |F4XRaYkFkeuHPl7rc+ruUTSAjC4GovxIxoDJFe0r4kbFmkiZOr40e8RZYK7T1IKr
        |Svzfxx5AjnlK/OZOTCq0L7wBPbMW+IxmQpFCjpI+yuoi3FlZG3LaLNrBMXQF/lLZ
        |UDHs77q3fAGxDWwum2hKBfdBuUQtjlqwjQlgXPsskQKBiQCyp5QmapcTcs/y1igi
        |MwgAqJOb2jqmw+VzwKssj0IfRRu5oDYkI4xwI2rxLJhtOqCdaUH1l9wCb9wWkDy1
        |hyL2bm9grwc3FCv7wVLdCjw31Enx3RTkKzAPMxh9GCEB9QbCaVaPmGnWlDMC6HBs
        |5cW3EodWww+HPUgG0X1jyO+CqBgctubKK7WbAnkAvSlgXQbvHzWmuUBFRHAejRh/
        |naQTDV3GnH4lcRHuFBFZCSLn82xQS2/7xFOqfabqq17kNcvKfzdvWpGxxJ2cILAq
        |0pZS6DmrZlvBU4IkK2ZHCac/XfWVZFh+PrsH/EnVkDpfcYR/iw1F40C1q5w8R6WB
        |Haew3SApAoGIaiodZsrWpi8HFfZfeRs8OS/0L5x6WBl3Y9btoZgsIeruc9uZ8NXT
        |IdxaM6FdnyNEyOYA1VH94tDYR+xEt1br1ud/dkPslLV/Aac7d7EaYc7cdkb7oC9t
        |6sphVg0dqE0UTDlOwBxBYMtGmQbJsFzGpmjzVgKqWqJ3B947li2U7t63HXEvKprY
        |2wJ4b0DzpSMb5p42dcQgOTU8Mr4S6JOEhRr/YjErMkpaXUEqvZ3jEB9HRmcRi5Gt
        |t4NBiBMiY6V9br8a5gjEpiAQoIUcWokBMAYjEeurU8M6JLBd3YaZVVjISaFmdtyn
        |wLFoQxCh6/EC1rSywwrfDpSwO29S9i8XbaapAoGIPkbARLOwU/LcZrQy9mmfcPoQ
        |lAuCyeu1Q9nH7PYSnbHTFzmiud4Hl8bIXU9a0/58blDoOl3PctF+b4rAEJYUpCOD
        |u5PFyN6uEFYRg+YQwpjBMkXk8Eb39128ctARB40Lx8caDhRdTyaEedIG3cQDXSpA
        |l9EOzXkzfx4bZxjAHU9mkMdJwOcMDQ==
        |-----END PRIVATE KEY-----""".stripMargin

    override def publicKey: PublicKeyPEM =
      """-----BEGIN RSA PUBLIC KEY-----
        |MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
        |WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
        |MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
        |kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
        |uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
        |PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
        |-----END RSA PUBLIC KEY-----""".stripMargin

    override def publicPk8Key =
      """-----BEGIN PUBLIC KEY-----
        |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhAKYdtoeoy8zcAcR874L
        |8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgaj
        |zrw3MOEt8uA5txSKobBpKDeBLOsdJKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTS
        |d/QBwVW9OwNFhekro3RtlinV0a75jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqG
        |TlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dS
        |FFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ1
        |0wIDAQAB
        |-----END PUBLIC KEY-----""".stripMargin

    override def keyAlg: AsymmetricKeyAlg = AsymmetricKeyAlg.RSA_PKCS_Key

    override def publicJwkKey: Map[String, String] = privateJwkKey
      .view
      .filterKeys { k => List("kty", "n", "e", "alg", "kid").contains(k) }
      .toMap

    override def privateJwkKey: Map[String, String] = Map(
      "kty" -> """RSA""",
      "kid" -> """test-key-rsa""",
      "p" -> """sqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOMcCNq8Sy\
  YbTqgnWlB9ZfcAm_cFpA8tYci9m5vYK8HNxQr-8FS3Qo8N9RJ8d0U5CswDzMYfRgh\
  AfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1mw""".rfc8792single,
      "q" -> """vSlgXQbvHzWmuUBFRHAejRh_naQTDV3GnH4lcRHuFBFZCSLn82xQS2_7xFO\
  qfabqq17kNcvKfzdvWpGxxJ2cILAq0pZS6DmrZlvBU4IkK2ZHCac_XfWVZFh-PrsH\
  _EnVkDpfcYR_iw1F40C1q5w8R6WBHaew3SAp""".rfc8792single,
      "d" -> """b8lm5JZ2hUduLnq-OAKCSODeWQ7Uqs7eet2bqeuAD0_2po-PG4qhZoo7VwF\
  CUTWlJan9wqdxiAPlbEQKkCdFRcbakbjN2TMJjMCHWL5zfgvqhmgeyKsrqg1wSce9\
  7J1_Mkvn3fh6CbqnwNb6bVFDvTJS3i5FzRhKiv6rUsYm8ZAdF4XRaYkFkeuHPl7rc\
  -ruUTSAjC4GovxIxoDJFe0r4kbFmkiZOr40e8RZYK7T1IKrSvzfxx5AjnlK_OZOTC\
  q0L7wBPbMW-IxmQpFCjpI-yuoi3FlZG3LaLNrBMXQF_lLZUDHs77q3fAGxDWwum2h\
  KBfdBuUQtjlqwjQlgXPsskQ""".rfc8792single,
      "e" -> """AQAB""",
      "qi" -> """PkbARLOwU_LcZrQy9mmfcPoQlAuCyeu1Q9nH7PYSnbHTFzmiud4Hl8bIXU\
  9a0_58blDoOl3PctF-b4rAEJYUpCODu5PFyN6uEFYRg-YQwpjBMkXk8Eb39128ctA\
  RB40Lx8caDhRdTyaEedIG3cQDXSpAl9EOzXkzfx4bZxjAHU9mkMdJwOcMDQ""".rfc8792single,
      "dp" -> """aiodZsrWpi8HFfZfeRs8OS_0L5x6WBl3Y9btoZgsIeruc9uZ8NXTIdxaM6\
  FdnyNEyOYA1VH94tDYR-xEt1br1ud_dkPslLV_Aac7d7EaYc7cdkb7oC9t6sphVg0\
  dqE0UTDlOwBxBYMtGmQbJsFzGpmjzVgKqWqJ3B947li2U7t63HXEvKprY2w""".rfc8792single,
      "dq" -> """b0DzpSMb5p42dcQgOTU8Mr4S6JOEhRr_YjErMkpaXUEqvZ3jEB9HRmcRi5\
  Gtt4NBiBMiY6V9br8a5gjEpiAQoIUcWokBMAYjEeurU8M6JLBd3YaZVVjISaFmdty\
  nwLFoQxCh6_EC1rSywwrfDpSwO29S9i8Xbaap""".rfc8792single,
      "n" -> """hAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrwWEBnez6\
  d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFqMGmXCQvE\
  G7YemcxDTRPxAleIAgYYRjTSd_QBwVW9OwNFhekro3RtlinV0a75jfZgkne_YiktS\
  vLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0PuKxI4T-HIa\
  Fpv8-rdV6eUgOrB2xeI1dSFFn_nnv5OoZJEIB-VmuKn3DCUcCZSFlQPSXSfBDiUGh\
  wOw76WuSSsf1D4b_vLoJ10w""".rfc8792single
    )

  }

  // 2048-bit RSA public and private key pair
  // taken from https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html#name-example-rsa-pss-key
  object `test-key-rsa-pss` extends TestKeyPair {
    override def description: String = "test-key-rsa-pss"

    // This was generated by converting the private key from spec into JWT and then using
    // pem-jwk node js lib to convert back to pem
    override def privateKey: PrivateKeyPEM =
      """-----BEGIN RSA PRIVATE KEY-----
        |MIIEpgIBAAKCAQEAr4tmm3r20Wd/PbqvP1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6d
        |pG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M
        |6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuY
        |LPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6
        |aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm
        |+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI2wIDAQABAoIBAQCUB8ip+kJiiZVK
        |F8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCqpbo360gvdt05H5VZ/RDVkEgO2k73VSsb
        |ulqezKs8RFs2tEmU+JgTI9MeQJPWcP6XaKy6LIYs0E2cWgp8GADgoBs8llBq0UhX
        |0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4XfK7lupFyo6HHyWRiYHMMARQXLJeOSdT
        |n5aMBP0PO4bQyk5ORxTUSeOciPJUFktQHkvGbym7KryEfwH8Tks0L7WhzyP60PL3
        |xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc
        |4dlexKYRAoGBAOVfuiEiOchGghV5vn5NRDNscAFnpHj1QgMr6/UG05RTgmcLfVsI
        |1I4bSkbrIuVKviGGf7atlkROALOG/xRxDLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB
        |67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPs
        |CHXte1uWNAqYad2WdLjPDlKtQJK1diCmrqmB2g8QE99hDOHItjDBEdpyFBKOIP+N
        |pVtM2KLhRajjcL9Ph8jrID6XUqikQuVi4J9FV2m42jXMuioTT13idAILanYg8D3i
        |dvy/3isDVkON0X3UAVKrgMEne0hJpkPLFYqgetvDAoGBAKLQ6JZMbSe0pPIJkSam
        |QhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/OGIHDRp6HjMUcxHpHw7U+S1TETxePwKL
        |nLKj6hw8jnX2/nZRgWHzgVcY+sPsReRxNJVf+Cfh6yOtznfX00p+JWOXdSY8glSS
        |HJwRAMog+hFGW1AYdt7w80XBAoGBAImRNUugqapgaEA8TrFxkJmngXYaAqpA0iYR
        |A7kv3S4QavPBUGtFJHBNULzitydkNtVZ3w6hgce0h9YThTo/nKc+OZDZbgfN9s7c
        |Q75x0PQCAO4fx2P91Q+mDzDUVTeG30mEt2m3S0dGe47JiJxifV9P3wNBNrZGSIF3
        |mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjNDdl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2
        |NdCzBliOmPyQtAr770GITWvbAI+IRYyFS7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AG
        |NaUTOJMs6NadzCmGPAxNQQOCqoUjn4XRrOjr9w349JooGXhOxbu8nOxX
        |-----END RSA PRIVATE KEY-----""".stripMargin

    override def privatePk8Key: PrivateKeyPEM =
      """-----BEGIN PRIVATE KEY-----
        |MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQCvi2abevbRZ389
        |uq8/Wzb5AS2+m5FpXxirjSCNRHzLZGPFrp2kbYZcds9+8yzxy34uHUYfjnHbxHDd
        |HLneab6gBePJDzo6cORnk3yVhuCAPg7fDozqkC8uSGT3kCd1OuJ9sgU81Tw88w7s
        |7KsUAeqAOzOeM8WZM60IRw3ZnUWlaByHC5gs8v5aiSqW13XWeqrOL5sn1y9IoANh
        |1QAA3lZS3N2mLLottOBLE/uhyJThOfSDkjpoNknsDwvOjQpLJligDjzmapw7QZUB
        |1XD2Wrho5P2/p36dvhuc2RBWSUtDd9UC8mb7F0M6n0sI0I3jxXamcM6QVXr5T2dX
        |mjJzpcjbAgMBAAECggEBAJQHyKn6QmKJlUoXwCp8H9pQ/SNMCo5B7ArWQon+JAJc
        |EKqlujfrSC923TkflVn9ENWQSA7aTvdVKxu6Wp7MqzxEWza0SZT4mBMj0x5Ak9Zw
        |/pdorLoshizQTZxaCnwYAOCgGzyWUGrRSFfQp9+CUh56Teftnoa3hgWB7ZMBxbZZ
        |s3hd8ruW6kXKjocfJZGJgcwwBFBcsl45J1OflowE/Q87htDKTk5HFNRJ45yI8lQW
        |S1AeS8ZvKbsqvIR/AfxOSzQvtaHPI/rQ8vfFL0U04mL2b7PO3BghcYNC4ozYYOwh
        |N4PaYjageg8zIAPTB0jsHBJVbXynWH6OB9zh2V7EphECgYEA5V+6ISI5yEaCFXm+
        |fk1EM2xwAWekePVCAyvr9QbTlFOCZwt9WwjUjhtKRusi5Uq+IYZ/tq2WRE4As4b/
        |FHEMtp2AER43IcvmXPqKFBoUktVDS7dThIHrsnRi1U7dHqVdwiMEMe5jxKNgnsKL
        |pnq+4NyhoS6OeWu1SFozG9J9xQkCgYEAw+wIde17W5Y0Cphp3ZZ0uM8OUq1AkrV2
        |IKauqYHaDxAT32EM4ci2MMER2nIUEo4g/42lW0zYouFFqONwv0+HyOsgPpdSqKRC
        |5WLgn0VXabjaNcy6KhNPXeJ0AgtqdiDwPeJ2/L/eKwNWQ43RfdQBUquAwSd7SEmm
        |Q8sViqB628MCgYEAotDolkxtJ7Sk8gmRJqZCGx6GAvlGznWJfibXPv6xgUAl+G83
        |dD84YgcNGnoeMxRzEekfDtT5LVMRPF4/AoucsqPqHDyOdfb+dlGBYfOBVxj6w+xF
        |5HE0lV/4J+HrI63Od9fTSn4lY5d1JjyCVJIcnBEAyiD6EUZbUBh23vDzRcECgYEA
        |iZE1S6CpqmBoQDxOsXGQmaeBdhoCqkDSJhEDuS/dLhBq88FQa0UkcE1QvOK3J2Q2
        |1VnfDqGBx7SH1hOFOj+cpz45kNluB832ztxDvnHQ9AIA7h/HY/3VD6YPMNRVN4bf
        |SYS3abdLR0Z7jsmInGJ9X0/fA0E2tkZIgXeas5EFU0MCgYEAjRAqfYi/tKCjhP9e
        |M0N2XaRlNeoYCTx06GlSLD8d0zc4ZZuEePY10LMGWI6Y/JC0CvvvQYhNa9sAj4hF
        |jIVLsWeTplVVUezGO1ofLW4kYWVpnMpHgAY1pRM4kyzo1p3MKYY8DE1BA4KqhSOf
        |hdGs6Ov3Dfj0migZeE7Fu7yc7Fc=
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
        |-----END PUBLIC KEY-----""".stripMargin

    override def privateJwkKey: Map[String, String] = Map(
      "kty" -> "RSA",
      "kid" -> "test-key-rsa-pss",
      "p" -> """5V-6ISI5yEaCFXm-fk1EM2xwAWekePVCAyvr9QbTlFOCZwt9WwjUjhtKRus\
  i5Uq-IYZ_tq2WRE4As4b_FHEMtp2AER43IcvmXPqKFBoUktVDS7dThIHrsnRi1U7d\
  HqVdwiMEMe5jxKNgnsKLpnq-4NyhoS6OeWu1SFozG9J9xQk""".rfc8792single,
      "q" -> """w-wIde17W5Y0Cphp3ZZ0uM8OUq1AkrV2IKauqYHaDxAT32EM4ci2MMER2nI\
  UEo4g_42lW0zYouFFqONwv0-HyOsgPpdSqKRC5WLgn0VXabjaNcy6KhNPXeJ0Agtq\
  diDwPeJ2_L_eKwNWQ43RfdQBUquAwSd7SEmmQ8sViqB628M""".rfc8792single,
      "d" -> """lAfIqfpCYomVShfAKnwf2lD9I0wKjkHsCtZCif4kAlwQqqW6N-tIL3bdOR-\
  VWf0Q1ZBIDtpO91UrG7pansyrPERbNrRJlPiYEyPTHkCT1nD-l2isuiyGLNBNnFoK\
  fBgA4KAbPJZQatFIV9Cn34JSHnpN5-2ehreGBYHtkwHFtlmzeF3yu5bqRcqOhx8lk\
  YmBzDAEUFyyXjknU5-WjAT9DzuG0MpOTkcU1EnjnIjyVBZLUB5Lxm8puyq8hH8B_E\
  5LNC-1oc8j-tDy98UvRTTiYvZvs87cGCFxg0LijNhg7CE3g9piNqB6DzMgA9MHSOw\
  cElVtfKdYfo4H3OHZXsSmEQ""".rfc8792single,
      "e" -> "AQAB",
      "qi" -> """jRAqfYi_tKCjhP9eM0N2XaRlNeoYCTx06GlSLD8d0zc4ZZuEePY10LMGWI\
  6Y_JC0CvvvQYhNa9sAj4hFjIVLsWeTplVVUezGO1ofLW4kYWVpnMpHgAY1pRM4kyz\
  o1p3MKYY8DE1BA4KqhSOfhdGs6Ov3Dfj0migZeE7Fu7yc7Fc""".rfc8792single,
      "dp" -> """otDolkxtJ7Sk8gmRJqZCGx6GAvlGznWJfibXPv6xgUAl-G83dD84YgcNGn\
  oeMxRzEekfDtT5LVMRPF4_AoucsqPqHDyOdfb-dlGBYfOBVxj6w-xF5HE0lV_4J-H\
  rI63Od9fTSn4lY5d1JjyCVJIcnBEAyiD6EUZbUBh23vDzRcE""".rfc8792single,
      "dq" -> """iZE1S6CpqmBoQDxOsXGQmaeBdhoCqkDSJhEDuS_dLhBq88FQa0UkcE1QvO\
  K3J2Q21VnfDqGBx7SH1hOFOj-cpz45kNluB832ztxDvnHQ9AIA7h_HY_3VD6YPMNR\
  VN4bfSYS3abdLR0Z7jsmInGJ9X0_fA0E2tkZIgXeas5EFU0M""".rfc8792single,
      "n" -> """r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvM\
  s8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95An\
  dTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11\
  nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSy\
  ZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V\
  2pnDOkFV6-U9nV5oyc6XI2w""".rfc8792single
    )

    override def publicJwkKey: Map[String, String] = privateJwkKey
      .view
      .filterKeys { k => List("kty", "n", "e", "alg", "kid").contains(k) }
      .toMap

    override def keyAlg: AsymmetricKeyAlg = AsymmetricKeyAlg.RSA_PSS_Key
  }

  object `test-key-ecc-p256` extends TestKeyPair {
    override def description: String = "test-key-ecc-p256"
    override def privateKey: PrivateKeyPEM =
      """-----BEGIN EC PRIVATE KEY-----
        |MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
        |AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
        |4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
        |-----END EC PRIVATE KEY-----""".stripMargin

    override def privatePk8Key: PrivateKeyPEM =
      """-----BEGIN PRIVATE KEY-----
        |MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgUpuF81l+kOxbjf7T
        |4mNSv0r5tN67Gim7rnf6EFpcYDugCgYIKoZIzj0DAQehRANCAASohVhlUsKs9kcY
        |eM/XsJNbT/4P0t/DQSSOoXvEHgWK8DHOJzfS0wzgYX6FHoPGHvVnnRUYZ2V2SQNd
        |kKdM2ehd
        |-----END PRIVATE KEY-----""".stripMargin

    override def publicKey: PublicKeyPEM =
      """-----BEGIN PUBLIC KEY-----
        |MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
        |w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
        |-----END PUBLIC KEY-----""".stripMargin

    override def privateJwkKey: Map[String, String] = Map(
      "kty" -> "EC",
      "crv" -> "P-256",
      "kid" -> "test-key-ecc-p256",
      "d" -> "UpuF81l-kOxbjf7T4mNSv0r5tN67Gim7rnf6EFpcYDs",
      "x" -> "qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA",
      "y" -> "Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0"
    )

    override def publicJwkKey: Map[String, String] =
      privateJwkKey.view.filterKeys(_ != "d").toMap
    override def keyAlg: AsymmetricKeyAlg = AsymmetricKeyAlg.ECKey(AsymmetricKeyAlg.`P-256`)

  }

  object `test-key-ed25519` extends TestKeyPair {
    override def description: String = "test-key-ed25519"

    override def privateKey: PrivateKeyPEM =
      """-----BEGIN PRIVATE KEY-----
        |MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
        |-----END PRIVATE KEY-----""".stripMargin

    override def publicKey: PublicKeyPEM =
      """-----BEGIN PUBLIC KEY-----
        |MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
        |-----END PUBLIC KEY-----""".stripMargin

    override def privateJwkKey: Map[String, String] = Map(
      "kty" -> "OKP",
      "crv" -> "Ed25519",
      "kid" -> "test-key-ed25519",
      "d" -> "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
      "x" -> "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    )
    override def keyAlg: AsymmetricKeyAlg = AsymmetricKeyAlg.Ed25519_Key

    /**
     * platform limitation descriptions that can be used to filter out tests and also provide
     * some readalbe documentation
     */
    override def limitation: Set[NotFor] = Set(
      NoWebCryptAPI(
        "At the moment: On 6 Nov 2022 only Node.js and Deno runtimes implement Ed25519 as per Secure Curves " +
          "in the Web Cryptography API.",
        List(
          new java.net.URI(
            "https://github.com/httpwg/http-extensions/issues/2290#issuecomment-1304763239"),
          new java.net.URI("https://wicg.github.io/webcrypto-secure-curves/")
        )
      ))
  }

}
