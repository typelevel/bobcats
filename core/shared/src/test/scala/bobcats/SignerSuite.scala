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

import bobcats.util.PEMUtils
import cats.MonadError
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
	type MonadErr[T[_]] = MonadError[T, Throwable]

	val tests: Seq[SignatureExample]

	implicit def signer: Signer[cats.effect.SyncIO]
	implicit def verifier: Verifier[cats.effect.SyncIO]
	implicit def pemutils: PEMUtils[cats.effect.SyncIO]


	def testSigner[F[_] : Signer : Verifier : MonadErr](
	  sigTest: SignatureExample, pubKey: PublicKeySpec[_], privKey: PrivateKeySpec[_]
	)(implicit ct: ClassTag[F[_]]): Unit = {

		val signature: F[ByteVector] = {
			val bytes: ByteVector = ByteVector.encodeAscii(sigTest.sigtext).toOption.get
			Signer[F].sign(privKey, sigTest.signatureAlg)(bytes)
		}

		test(s"signature verification with public key for ${sigTest.description}") {
			val headersVec = ByteVector.encodeAscii(sigTest.sigtext).toOption.get //because these are headers!
			for {
				signedTxt <- signature
				b <- Verifier[F].verify(pubKey, sigTest.signatureAlg)(headersVec, signedTxt)
			} yield {
				assertEquals(b, true,
					s"expected verify(>>${sigTest.sigtext}<<, >>$signedTxt<<)=true)"
				)
			}
		}

		test(s"test ${sigTest.description} against expected value") {
			signature.map { signed =>
				assertEquals(
					signed.toBase64(Alphabets.Base64), sigTest.signature,
					s"inputStr was >>${sigTest.sigtext}<<"
				)
			}
		}
	}

	if (BuildInfo.runtime == "JVM") {
		tests.foreach { sigTest =>
			val pub: PublicKeySpec[_] = pemutils.getPublicKeyFromPEM(sigTest.keys.publicKey).unsafeRunSync()
			val priv: PrivateKeySpec[_] = pemutils.getPrivateKeyFromPEM(sigTest.keys.privateKey).unsafeRunSync()
			testSigner[SyncIO](sigTest, pub, priv)
		}
	}
}
