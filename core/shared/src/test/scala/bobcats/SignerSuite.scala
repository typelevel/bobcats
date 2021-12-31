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
import cats.syntax.all._
import munit.CatsEffectSuite
import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector

import scala.reflect.ClassTag
import scala.util.Try

/*
 * todo: does one need CatsEffectSuite?  (We don't use assertIO, ...)
 */
trait SignerSuite extends CatsEffectSuite {
	type MonadErr[T[_]] = MonadError[T, Throwable]

	val tests: Seq[SignatureExample] = SigningHttpMessages.signatureExamples

	def pemutils: PEMUtils

	def testSigner[F[_] : Signer : Verifier : MonadErr](
	  sigTest: SignatureExample, pubKey: PublicKeySpec[_], privKey: PrivateKeySpec[_]
	)(implicit ct: ClassTag[F[_]]): Unit = {

		test(s"signature verification with public key for ${sigTest.description}") {
			for {
				sigTextBytes <- implicitly[MonadErr[F]].fromEither(ByteVector.encodeAscii(sigTest.sigtext))
				signedTxt <- Signer[F].sign(privKey, sigTest.signatureAlg)(sigTextBytes)
				b <- Verifier[F].verify(pubKey, sigTest.signatureAlg)(
					sigTextBytes, signedTxt
				)
			} yield {
				assertEquals(b, true, s"expected verify(>>${sigTest.sigtext}<<, >>$signedTxt<<)=true)")
			}
		}

		test(s"test ${sigTest.description} against expected value") {
			for {
				sigTextBytes <- implicitly[MonadErr[F]].fromEither(ByteVector.encodeAscii(sigTest.sigtext))
				expectedSig <-  implicitly[MonadErr[F]].fromEither(
					ByteVector.fromBase64Descriptive(sigTest.signature, scodec.bits.Bases.Alphabets.Base64)
					  .leftMap(new Exception(_))
				)
				b <- Verifier[F].verify(pubKey, sigTest.signatureAlg)(
					sigTextBytes, expectedSig
				)
			} yield {
				assertEquals(b, true,
					s"expected to verify >>${sigTest.sigtext}<<"
				)
			}
		}
	}

	def extractKeys(ex: SignatureExample): (PublicKeySpec[AsymmetricKeyAlg], PrivateKeySpec[AsymmetricKeyAlg]) = {
		val res: Try[(PublicKeySpec[AsymmetricKeyAlg], PrivateKeySpec[AsymmetricKeyAlg])] = for {
			pub <- pemutils.getPublicKeyFromPEM(ex.keys.publicKeyNew, ex.keys.keyAlg)
			priv <- pemutils.getPrivateKeyFromPEM(ex.keys.privatePk8Key, ex.keys.keyAlg)
		} yield (pub, priv)

		test(s"parsing public and private keys for ${ex.description}") {
			res.get
		}
		res.get
	}

	// subclasses should call run
	def run[F[_]: Signer : Verifier : MonadErr](
	  tests: Seq[SignatureExample]
	): Unit = {
		tests.foreach { sigTest =>
		  //using flatmap here would not work as F is something like IO that would
		  //delay the flapMap, meaning the tests would then not get registered.
			val keys = extractKeys(sigTest)
			testSigner[F](sigTest, keys._1, keys._2)
		}
	}
}
