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

import cats.FlatMap
import cats.effect.SyncIO
import cats.syntax.all._
import munit.CatsEffectSuite
import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector

import scala.reflect.ClassTag

/*
 * todo: Extract interface from SigingHttpMessages to allow
 *  other test examples from other specs to be added.
 */
trait SignerSuite extends CatsEffectSuite {
	val tests: SigningHttpMessages
	import tests._

	def testSigner[F[_] : Signer : Verifier : FlatMap](
	  sigTest: SignatureTest
	)(implicit ct: ClassTag[F[_]]): Unit = {
		def privKey: PrivateKeySpec[_] = sigTest.privateKeySpec.get
		def pubKey: PublicKeySpec[_] = sigTest.pubKeySpec.get

		test(s"preconditions for ${sigTest.description} using ${sigTest.alg} with ${ct.runtimeClass.getSimpleName()}") {
			assert(sigTest.privateKeySpec.isSuccess)
			assert(sigTest.pubKeySpec.isSuccess)
		}

		val signature: F[ByteVector] = 	{
			val bytes: ByteVector = ByteVector.encodeAscii(sigTest.text).toOption.get
			Signer[F].sign(privKey, sigTest.alg)(bytes)
		}

		test(s"signature verification with public key for ${sigTest.description}") {
			val headersVec = ByteVector.encodeAscii(sigTest.text).toOption.get //because these are headers!
			for {
				signedTxt <- signature
				b <- Verifier[F].verify(pubKey, sigTest.alg)(headersVec, signedTxt)
			} yield {
				println(s"verified '${sigTest.description}' signature")
				assertEquals(b, true,
					s"expected verify(>>${sigTest.text}<<, >>$signedTxt<<)=true)"
				)
			}
		}

		test(s"test ${sigTest.description} against expected value"){
		   signature.map { signed =>
				assertEquals(
					signed.toBase64(Alphabets.Base64), sigTest.sig,
					s"inputStr was >>${sigTest.text}<<"
				)
			}
		}
	}

	if (BuildInfo.runtime == "JVM") {
		tests.signatureTests.map { sigTest =>
			testSigner[SyncIO](sigTest)
		}
	}
}
