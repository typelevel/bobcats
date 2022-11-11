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
import cats.effect.Sync
import cats.effect.std.Random
import cats.syntax.all._
import cats.{Applicative, MonadError}
import munit.CatsEffectSuite
import scodec.bits.ByteVector

import scala.reflect.ClassTag
import scala.util.Try

/*
 * Suite for testing signatures.
 */
trait SignerSuite extends CatsEffectSuite {
  type MonadErr[T[_]] = MonadError[T, Throwable]

  def pemutils: PEMUtils

  def alterOneRandomChar[F[_]: Applicative: Random](signingStr: String): F[String] = {
    import cats.implicits._
    (Random[F].nextAlphaNumeric, Random[F].betweenInt(0, signingStr.length)).mapN { (c, ri) =>
      // we make our life easy, since we can make the string longer
      if (ri == 0 || signingStr.charAt(ri) == c) { signingStr + c }
      else {
        val (a, b) = signingStr.splitAt(ri)
        a + c + b.tail
      }
    }
  }

  def testSymmetricSigner[F[_]: Hmac: MonadErr](
      typedSignatures: Seq[SymmetricSignatureExample] // these are non-empty lists
  )(implicit ct: ClassTag[F[Nothing]]): Unit = {
    val prototype = typedSignatures.head
    val bytesV = ByteVector.fromBase64Descriptive(prototype.key.sharedKey)
    test(
      s"Symmetric ${typedSignatures.head.key.description} in ${typedSignatures.head.description} build key") {
      assert(bytesV.isRight, bytesV)
    }
    val keyF = Hmac[F].importKey(bytesV.toOption.get, prototype.signatureAlg)
    typedSignatures.foreach { symTest =>
      test(
        s"${symTest.description} with ${ct.runtimeClass.getSimpleName()}: digest matches expected") {
        for {
          expectedBytes <- MonadError[F, Throwable].fromEither(
            ByteVector.fromBase64Descriptive(symTest.signature).leftMap(new Exception(_)))
          key <- keyF
          sigTextBytes <- MonadError[F, Throwable].fromEither(
            ByteVector.encodeAscii(symTest.sigtext).leftMap(new Exception(_)))
          digest <- Hmac[F].digest(key, sigTextBytes)
        } yield assertEquals(digest, expectedBytes)
      }
    }
  }

  def testSigner[F[_]: Signer: Verifier: Sync](
      publicKey: PublicKey[_],
      privateKey: PrivateKey[_],
      signatureAlg: AsymmetricKeyAlg.Signature,
      typedSignatures: Seq[SignatureExample] // these are non-empty lists
  )(implicit ct: ClassTag[F[Nothing]]): Unit = {
    val signerF = Signer[F].build(privateKey, signatureAlg)
    val verifierF = Verifier[F].build(publicKey, signatureAlg)

    def signatureTxtF(signingStr: String): F[ByteVector] =
      implicitly[MonadErr[F]].fromEither(ByteVector.encodeAscii(signingStr))

    // todo: extract the signer and verifier from signerF and verifierF and then run these
    //    tests, so that we can test that we only need to construct those objects once.
    //    not sure how to do that with munit
    typedSignatures.foreach { sigTest =>
      test(
        s"${sigTest.keypair.description} ${sigTest.signatureAlg} ${ct.runtimeClass.getSimpleName()}: verify generated ex."
      ) {
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
        s"${sigTest.keypair.description} ${sigTest.signatureAlg} ${ct.runtimeClass.getSimpleName()}: matches expected in ${sigTest.description}") {
        for {
          verify <- verifierF
          sigTextBytes <- signatureTxtF(sigTest.sigtext)
          expectedSig <- implicitly[MonadErr[F]].fromEither(
            ByteVector
              .fromBase64Descriptive(sigTest.signature, scodec.bits.Bases.Alphabets.Base64)
              .leftMap(new Exception(_))
          )
          b <- verify(sigTextBytes, expectedSig)
          // next create a broken signature
          random <- Random.scalaUtilRandom[F]
          brokenText <- {
            implicit val r: Random[F] = random
            alterOneRandomChar(sigTest.sigtext)
          }
          sigBrokenTxtBytes <- signatureTxtF(brokenText)
          b2 <- verify(sigBrokenTxtBytes, expectedSig)
        } yield {
          assertEquals(b, true, s"expected to verify >>${sigTest.sigtext}<<")
          assertEquals(b2, false, s"expected not to verify altered text >>${brokenText}<<")
        }
      }
    }

  }

  def extractKeysPem(ex: SignatureExample)
      : Try[(SPKIKeySpec[AsymmetricKeyAlg], PKCS8KeySpec[AsymmetricKeyAlg])] =
    for {
      pub <- pemutils.getPublicKeySpec(ex.keypair.publicPk8Key, ex.keypair.keyAlg)
      priv <- pemutils.getPrivateKeySpec(ex.keypair.privatePk8Key, ex.keypair.keyAlg)
    } yield (pub, priv)

  /**
   * create a class that statically calls run on startup. The `foreach` calls on existing data
   * structures like `tests` runs the code which caputres any test creations adding them to the
   * test DB to be executed later. Those tests can return IO Monads.
   */
  def run[F[_]: Signer: Verifier: Sync](
      tests: Seq[SignatureExample]
  )(implicit ct: ClassTag[F[Nothing]]): Unit = {
    tests.groupBy(ex => (ex.keypair.publicKey, ex.signatureAlg)).values.foreach { sigTests =>
      val prototype = sigTests.head
      val keypair: Try[(SPKIKeySpec[AsymmetricKeyAlg], PKCS8KeySpec[AsymmetricKeyAlg])] =
        extractKeysPem(prototype)
      test(s"${sigTests.head.keypair.description}: build PEM based keys " +
        s"for following ${sigTests.size} tests with ${sigTests.head.signatureAlg}") {
        assert(keypair.isSuccess, keypair.toString)
      }
      val (pubKey, privKey) = keypair.get
      testSigner[F](pubKey, privKey, prototype.signatureAlg, sigTests)
      val pubJwk = JWKPublicKeySpec(prototype.keypair.publicJwkKey, prototype.keypair.keyAlg)
      val privJwk = JWKPrivateKeySpec(prototype.keypair.privateJwkKey, prototype.keypair.keyAlg)
      test(s"${sigTests.head.keypair.description}: build JWK based keys " +
        s"for following ${sigTests.size} tests with ${sigTests.head.signatureAlg})") {
        assert(pubJwk != null)
        assert(privJwk != null)
        // see if one can have tests inside tests...
      }
      // is that going to work to just pass the same key in both?
      testSigner[F](pubJwk, privJwk, prototype.signatureAlg, sigTests)

    }
  }

  /**
   * same as with run above
   */
  def runSym[F[_]: Hmac: MonadErr](
      tests: Seq[SymmetricSignatureExample]
  )(implicit ct: ClassTag[F[Nothing]]): Unit = {
    tests.groupBy(ex => (ex.key, ex.signatureAlg)).values.foreach { sigTests =>
      testSymmetricSigner[F](sigTests)
    }
  }
}
