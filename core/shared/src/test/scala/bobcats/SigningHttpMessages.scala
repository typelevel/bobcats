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
 * @see https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html
 */
object SigningHttpMessages extends SignatureExamples {

	def signatureExamples: Seq[SignatureExample] = Seq(
		`§3.1_Signature`,
		`§4.3_Example`,
		`Appendix_B.2.1`,
		`Appendix_B.2.4`
	)

	override def keyExamples: Seq[TestKeys] = Seq(
		`test-key-rsa`,
		`test-key-rsa-pss`,
		`test-key-ecc-p256`
	)

	object `§3.1_Signature` extends SignatureExample(
		description = "§3.1_Signature example",
		sigtext = // defined https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html#section-2.3
			""""@method": GET
			  |"@path": /foo
			  |"@authority": example.org
			  |"cache-control": max-age=60, must-revalidate
			  |"x-empty-header":
			  |"x-example": Example header with some whitespace.
			  |"@signature-params": ("@method" "@path" "@authority" \
			  |  "cache-control" "x-empty-header" "x-example");created=1618884475\
			  |  ;keyid="test-key-rsa-pss"""".rfc8792single,
		signature =
			"""P0wLUszWQjoi54udOtydf9IWTfNhy+r53jGFj9XZuP4uKwxyJo1RSHi+oEF1FuX6O29\
			  |d+lbxwwBao1BAgadijW+7O/PyezlTnqAOVPWx9GlyntiCiHzC87qmSQjvu1CFyFuWSj\
			  |dGa3qLYYlNm7pVaJFalQiKWnUaqfT4LyttaXyoyZW84jS8gyarxAiWI97mPXU+OVM64\
			  |+HVBHmnEsS+lTeIsEQo36T3NFf2CujWARPQg53r58RmpZ+J9eKR2CD6IJQvacn5A4Ix\
			  |5BUAVGqlyp8JYm+S/CWJi31PNUjRRCusCVRj05NrxABNFv3r5S9IXf2fYJK+eyW4AiG\
			  |VMvMcOg==""".rfc8792single,
		keys =	`test-key-rsa-pss`,
		signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
	)

	object `Appendix_B.2.1` extends SignatureExample(
		description = "Appendix_B.2.1 minimal example",
		sigtext =
			""""@signature-params": ();created=1618884475\
			  |  ;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"""".rfc8792single,
		signature =
			"""HWP69ZNiom9Obu1KIdqPPcu/C1a5ZUMBbqS/xwJECV8bhIQVmE\
			  |AAAzz8LQPvtP1iFSxxluDO1KE9b8L+O64LEOvhwYdDctV5+E39Jy1eJiD7nYREBgx\
			  |TpdUfzTO+Trath0vZdTylFlxK4H3l3s/cuFhnOCxmFYgEa+cw+StBRgY1JtafSFwN\
			  |cZgLxVwialuH5VnqJS4JN8PHD91XLfkjMscTo4jmVMpFd3iLVe0hqVFl7MDt6TMkw\
			  |IyVFnEZ7B/VIQofdShO+C/7MuupCSLVjQz5xA+Zs6Hw+W9ESD/6BuGs6LF1TcKLxW\
			  |+5K+2zvDY/Cia34HNpRW5io7Iv9/b7iQ==""".rfc8792single,
		keys = `test-key-rsa-pss`,
		signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
	)

	object `Appendix_B.2.2` extends SignatureExample(
		description = "Appendix_B.2.2 selective header example",
		sigtext =
			""""@authority": example.com
			  |"content-type": application/json
			  |"@signature-params": ("@authority" "content-type")\
			  |  ;created=1618884475;keyid="test-key-rsa-pss"""".rfc8792single,
		signature =
			"""ik+OtGmM/kFqENDf9Plm8AmPtqtC7C9a+zYSaxr58b/E6h81gh\
			  |  JS3PcH+m1asiMp8yvccnO/RfaexnqanVB3C72WRNZN7skPTJmUVmoIeqZncdP2mlf\
			  |  xlLP6UbkrgYsk91NS6nwkKC6RRgLhBFqzP42oq8D2336OiQPDAo/04SxZt4Wx9nDG\
			  |  uy2SfZJUhsJqZyEWRk4204x7YEB3VxDAAlVgGt8ewilWbIKKTOKp3ymUeQIwptqYw\
			  |  v0l8mN404PPzRBTpB7+HpClyK4CNp+SVv46+6sHMfJU4taz10s/NoYRmYCGXyadzY\
			  |  YDj0BYnFdERB6NblI/AOWFGl5Axhhmjg==""".rfc8792single,
		keys = `test-key-rsa-pss`,
		signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
	)

	object `Appendix_B.2.3` extends SignatureExample(
		description = "Appendix_B.2.3 full coverage example",
		sigtext =
			""""date": Tue, 20 Apr 2021 02:07:56 GMT
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
		signature =
			"""JuJnJMFGD4HMysAGsfOY6N5ZTZUknsQUdClNG51VezDgPUOW03\
			  |  QMe74vbIdndKwW1BBrHOHR3NzKGYZJ7X3ur23FMCdANe4VmKb3Rc1Q/5YxOO8p7Ko\
			  |  yfVa4uUcMk5jB9KAn1M1MbgBnqwZkRWsbv8ocCqrnD85Kavr73lx51k1/gU8w673W\
			  |  T/oBtxPtAn1eFjUyIKyA+XD7kYph82I+ahvm0pSgDPagu917SlqUjeaQaNnlZzO03\
			  |  Iy1RZ5XpgbNeDLCqSLuZFVID80EohC2CQ1cL5svjslrlCNstd2JCLmhjL7xV3NYXe\
			  |  rLim4bqUQGRgDwNJRnqobpS6C1NBns/Q==""".rfc8792single,
		keys = `test-key-rsa-pss`,
		signatureAlg = AsymmetricKeyAlg.`rsa-pss-sha512`
	)

	object `Appendix_B.2.4` extends SignatureExample(
		description = "Appendix_B.2.4 Elliptic Curve example",
		sigtext =
			""""content-type": application/json
			  |"digest": SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
			  |"content-length": 18
			  |"@signature-params": ("content-type" "digest" "content-length")\
			  |  ;created=1618884475;keyid="test-key-ecc-p256"""".rfc8792single,
		signature =
			"""n8RKXkj0iseWDmC6PNSQ1GX2R9650v+lhbb6rTGoSrSSx18zmn\
			  |  6fPOtBx48/WffYLO0n1RHHf9scvNGAgGq52Q==""".rfc8792single,
		keys = `test-key-ecc-p256`,
		signatureAlg = AsymmetricKeyAlg.`ecdsa-p256-sha256`
	)

	object `§4.3_Example` extends SignatureExample(
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
		signature =
			"""cjGvZwbsq9JwexP9TIvdLiivxqLINwp/ybAc19KOSQuLvtmMt3EnZxNiE+797dXK2cj\
			  |PPUFqoZxO8WWx1SnKhAU9SiXBr99NTXRmA1qGBjqus/1Yxwr8keB8xzFt4inv3J3zP0\
			  |k6TlLkRJstkVnNjuhRIUA/ZQCo8jDYAl4zWJJjppy6Gd1XSg03iUa0sju1yj6rcKbMA\
			  |BBuzhUz4G0u1hZkIGbQprCnk/FOsqZHpwaWvY8P3hmcDHkNaavcokmq+3EBDCQTzgwL\
			  |qfDmV0vLCXtDda6CNO2Zyum/pMGboCnQn/VkQ+j8kSydKoFg6EbVuGbrQijth6I0dDX\
			  |2/HYcJg==""".rfc8792single,
		keys= `test-key-rsa`,
		signatureAlg = AsymmetricKeyAlg.`rsa-v1_5-sha256`
	)


	// 2048-bit RSA public and private key pair,
	// given in https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html#appendix-B.1.1
	object `test-key-rsa` extends TestKeys {
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

		override def publicKeyNew =
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

	}

	// 2048-bit RSA public and private key pair
	// taken from https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html#name-example-rsa-pss-key
	object `test-key-rsa-pss` extends TestKeys {
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
			  |-----END PUBLIC KEY-----""".stripMargin

		override def keyAlg: AsymmetricKeyAlg = AsymmetricKeyAlg.RSA_PSS_Key
	}

	object `test-key-ecc-p256` extends TestKeys {
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

		override def keyAlg: AsymmetricKeyAlg = AsymmetricKeyAlg.ECKey(AsymmetricKeyAlg.`P-256`)

	}

}