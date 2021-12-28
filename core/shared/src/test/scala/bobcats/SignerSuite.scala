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
	type IOX[+X]

	val tests: Seq[SignatureExample] = SigningHttpMessages.signatureExamples

	//the only time we have to really decide between IOX being sync or async is in
	// the PEMUtils as `extract` calls the unsafe methods
	def pemutils: PEMUtils[IOX]

	// either unsafeRunSync() or unsafeRunASync()
	def extractPub(a: IOX[PublicKeySpec[PKA]]): Try[PublicKeySpec[PKA]]
	def extractPriv(a: IOX[PrivateKeySpec[PrivateKeyAlg]]): Try[PrivateKeySpec[PrivateKeyAlg]]


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

	def extractKeys(ex: SignatureExample): (PublicKeySpec[PKA], PrivateKeySpec[PrivateKeyAlg]) = {
		val res: Try[(PublicKeySpec[PKA], PrivateKeySpec[PrivateKeyAlg])] = for {
			pub <- extractPub(pemutils.getPublicKeyFromPEM(ex.keys.publicKey))
			priv <- extractPriv(pemutils.getPrivateKeyFromPEM(ex.keys.privateKey))
		} yield (pub, priv)

		test(s"parsing public and private keys for ${ex.description}") {
			res.get
		}
		res.get.asInstanceOf[(PublicKeySpec[PKA], PrivateKeySpec[PrivateKeyAlg])]
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
