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

import bobcats.util.StringUtils._
import cats.Functor
import cats.effect.SyncIO
import cats.syntax.all._
import munit.CatsEffectSuite
import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector

import java.nio.charset.CharacterCodingException
import scala.reflect.ClassTag

/* this is in the jvm tree until the public key parsing is done
 * Examples keys and signatures are taken from
 * https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html#name-signature-parameters
 */
class SignerSuite extends CatsEffectSuite {

	java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider)

	def testSigner[F[_]: Signer: Functor, A <: PrivateKeyAlg](
	  pks: PrivateKeySpec[A], sig: PKA.Signature,
	  inputStr: String, expect: String
	)(implicit ct: ClassTag[F[_]]): Unit =
		test(s"$sig with ${ct.runtimeClass.getSimpleName()}") {
			val bytes: Either[CharacterCodingException, ByteVector] =
				ByteVector.encodeAscii(inputStr)
			bytes match {
				case Left(error) => fail("could not turn input string into a byte vector?",error)
				case Right(sigBytes) => Signer[F].sign(pks, sig, sigBytes).map { signed =>
					 assertEquals(
						 signed.toBase64(Alphabets.Base64), expect,
						 s"inputStr was >>$inputStr<<"
					 )
				}
			}
		}

	if (BuildInfo.runtime == "JVM") {
		println(s"PrivKey >>${SigningHttpMessages.pkspecBytes}<<")
		SigningHttpMessages.sigString_Sig_Seq.map { case (in, out) =>
			testSigner[SyncIO, PKA.RSA.Private](
				SigningHttpMessages.pkspec.right.get, PKA.`rsa-pss-sha512`,
				in, out
			)
		}
	}
}

/**
 * Examples taken from Signing HTTP Messages RFC draft
 * @see https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html
 */
object SigningHttpMessages {

	lazy val sigString_Sig_Seq: Seq[(String, String)] = Seq(
		sigInputStrExpected -> signatureStr,
		`sigInput_B.2.1` -> `signatureStr_B.2.1`
	)

	val sigInputStrExpected =
		""""@method": GET
		  |"@path": /foo
		  |"@authority": example.org
		  |"cache-control": max-age=60, must-revalidate
		  |"x-empty-header":
		  |"x-example": Example header with some whitespace.
		  |"@signature-params": ("@method" "@path" "@authority" \
		  |  "cache-control" "x-empty-header" "x-example");created=1618884475\
		  |  ;keyid="test-key-rsa-pss"""".stripMargin.rfc8792single

	val signatureStr =
		"""P0wLUszWQjoi54udOtydf9IWTfNhy+r53jGFj9XZuP4uKwxyJo1RSHi+oEF1FuX6O29\
		  |d+lbxwwBao1BAgadijW+7O/PyezlTnqAOVPWx9GlyntiCiHzC87qmSQjvu1CFyFuWSj\
		  |dGa3qLYYlNm7pVaJFalQiKWnUaqfT4LyttaXyoyZW84jS8gyarxAiWI97mPXU+OVM64\
		  |+HVBHmnEsS+lTeIsEQo36T3NFf2CujWARPQg53r58RmpZ+J9eKR2CD6IJQvacn5A4Ix\
		  |5BUAVGqlyp8JYm+S/CWJi31PNUjRRCusCVRj05NrxABNFv3r5S9IXf2fYJK+eyW4AiG\
		  |VMvMcOg==""".stripMargin.rfc8792single

	val `sigInput_B.2.1` =
		""""@signature-params": ();created=1618884475\
		  |  ;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"""".stripMargin.rfc8792single

	val `signatureStr_B.2.1` =
		"""HWP69ZNiom9Obu1KIdqPPcu/C1a5ZUMBbqS/xwJECV8bhIQVmE\
		  |  AAAzz8LQPvtP1iFSxxluDO1KE9b8L+O64LEOvhwYdDctV5+E39Jy1eJiD7nYREBgx\
		  |  TpdUfzTO+Trath0vZdTylFlxK4H3l3s/cuFhnOCxmFYgEa+cw+StBRgY1JtafSFwN\
		  |  cZgLxVwialuH5VnqJS4JN8PHD91XLfkjMscTo4jmVMpFd3iLVe0hqVFl7MDt6TMkw\
		  |  IyVFnEZ7B/VIQofdShO+C/7MuupCSLVjQz5xA+Zs6Hw+W9ESD/6BuGs6LF1TcKLxW\
		  |  +5K+2zvDY/Cia34HNpRW5io7Iv9/b7iQ==""".stripMargin.rfc8792single


	/**
	 * Public and Private keys from [[https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-04.html#section-b.1.1 Message Signatures §Appendix B.1.1]]
	 * Obviously, these should not be used other than for test cases!
	 * So place them here to make them available in other tests.
	 **/
	val `test-key-rsa-pss-public`: String =
	"""MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
	  |+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
	  |oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
	  |gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
	  |Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
	  |aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
	  |2wIDAQAB""".stripMargin.rfc8792single

	val `test-key-rsa-pss-private`: String =
	"""MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
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
	  |rOjr9w349JooGXhOxbu8nOxX""".stripMargin.rfc8792single

	lazy val pkspecBytes: Either[String, ByteVector] =
		ByteVector.fromBase64Descriptive(`test-key-rsa-pss-private`, Alphabets.Base64)

	lazy val pkspec: Either[String, PrivateKeySpec[PrivateKeyAlg.RSA.type]] = pkspecBytes.map( bytes =>
		PrivateKeySpec(bytes,PKA.RSA.Private)
	)


}