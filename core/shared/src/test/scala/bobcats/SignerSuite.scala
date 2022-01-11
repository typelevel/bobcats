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

  def testSigner[F[_]: Signer: Verifier: MonadErr](
      typedSignatures: Seq[SignatureExample] // these are non-empty lists
  )(implicit ct: ClassTag[F[_]]): Unit = {
    val prototype = typedSignatures.head
    val keypair: Try[(SPKIKeySpec[AsymmetricKeyAlg], PKCS8KeySpec[AsymmetricKeyAlg])] =
      extractKeys(prototype)
    test(s"${typedSignatures.head.keypair.description}: build key " +
      s"spec for following ${typedSignatures.size} tests with ${typedSignatures.head.signatureAlg}") {
      assert(keypair.isSuccess, keypair.toString)
    }
    val (pubKey, privKey) = keypair.get
    val signerF = Signer[F].build(privKey, prototype.signatureAlg)
    val verifierF = Verifier[F].build(pubKey, prototype.signatureAlg)

    def signatureTxtF(signingStr: String): F[ByteVector] =
      implicitly[MonadErr[F]].fromEither(ByteVector.encodeAscii(signingStr))

    // todo: extract the signer and verifier from signerF and verifierF and then run these
    //    tests, so that we can test that we only need to construct those objects once.
    //    not sure how to do that with munit
    typedSignatures.foreach { sigTest =>
      test(
        s"${sigTest.description} with ${ct.runtimeClass.getSimpleName()}: can verify generated signature") {
        for {
          sign <- signerF
          verify <- verifierF
          sigTextBytes <- signatureTxtF(sigTest.sigtext)
          // todo here it would be good to have a Seq of sigTest examples to test with the same sigFn
          signedTxt <- sign(sigTextBytes)
          b <- verify(sigTextBytes, signedTxt)
        } yield {
          assertEquals(
            b,
            true,
            s"expected verify(>>${sigTest.sigtext}<<, >>$signedTxt<<)=true)")
        }
      }

      test(
        s"${sigTest.description} with ${ct.runtimeClass.getSimpleName()}: matches expected value") {
        for {
          verify <- verifierF
          sigTextBytes <- signatureTxtF(sigTest.sigtext)
          expectedSig <- implicitly[MonadErr[F]].fromEither(
            ByteVector
              .fromBase64Descriptive(sigTest.signature, scodec.bits.Bases.Alphabets.Base64)
              .leftMap(new Exception(_))
          )
          b <- verify(sigTextBytes, expectedSig)
        } yield {
          assertEquals(b, true, s"expected to verify >>${sigTest.sigtext}<<")
        }
      }
    }

  }

  // using flatmap  would not work as F is something like IO that would
  // delay the flapMap, meaning the tests would then not get registered.
  def extractKeys(ex: SignatureExample)
      : Try[(SPKIKeySpec[AsymmetricKeyAlg], PKCS8KeySpec[AsymmetricKeyAlg])] =
    for {
      pub <- pemutils.getPublicKeySpec(ex.keypair.publicPk8Key, ex.keypair.keyAlg)
      priv <- pemutils.getPrivateKeySpec(ex.keypair.privatePk8Key, ex.keypair.keyAlg)
    } yield (pub, priv)

  // subclasses should call run
  def run[F[_]: Signer: Verifier: MonadErr](
      tests: Seq[SignatureExample]
  )(implicit ct: ClassTag[F[_]]): Unit = {
    tests.groupBy(ex => (ex.keypair.publicKey, ex.signatureAlg)).values.foreach { sigTests =>
      testSigner[F](sigTests)
    }
  }
}
