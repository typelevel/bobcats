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

import cats.effect.kernel.{Async, Sync}
import scodec.bits.ByteVector
import cats.effect.std.SecureRandom
import cats.syntax.all._
import java.security.Provider
import javax.crypto.spec.{GCMParameterSpec, IvParameterSpec}
import javax.crypto
import java.nio.ByteBuffer

private final class JavaSecurityCipher[F[_]](providers: Providers)(implicit F: Sync[F])
    extends UnsealedCipher[F] {

  import BlockCipherAlgorithm._

  private def aesCipherName(keyLength: AES.KeyLength, mode: BlockCipherMode, padding: Boolean): String =
    s"AES_${keyLength.toInt.toString}/${mode.toStringUppercase}/" + (if (padding) "PKCS5Padding" else "NoPadding")

  def importKey[A <: Algorithm](
      key: ByteVector,
      algorithm: A): F[SecretKey[A]] =
    F.pure(SecretKeySpec(key, algorithm))

  def encrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector] = {

    F.catchNonFatal {
      val (cipher, out) = (key.algorithm, params) match {
        case (cbc: AES.CBC, AES.CBC.Params(iv)) =>
          val name = aesCipherName(cbc.keyLength, BlockCipherMode.CBC, false)
          val provider = providers.cipher(name) match {
            case Left(e) => throw e
            case Right(p) => p
          }
          val cipher = crypto.Cipher.getInstance(name, provider)
          cipher.init(
            crypto.Cipher.ENCRYPT_MODE,
            key.toJava,
            new IvParameterSpec(iv.data.toArray))
          // TODO: Calculate length properly
          val len = data.length.toInt
          (cipher, ByteBuffer.allocate(len))
        case (gcm: AES.GCM, AES.GCM.Params(iv, tagLength, ad)) =>
          val name = aesCipherName(gcm.keyLength, BlockCipherMode.GCM, false)
          val provider = providers.cipher(name) match {
            case Left(e) => throw e
            case Right(p) => p
          }
          val cipher = crypto.Cipher.getInstance(name, provider)
          cipher.init(
            crypto.Cipher.ENCRYPT_MODE,
            key.toJava,
            new GCMParameterSpec(tagLength.value, iv.data.toArray))

          ad.foreach { data => cipher.updateAAD(data.toByteBuffer) }
          // TODO: Calculate length properly
          ???
      }
      cipher.doFinal(data.toByteBuffer, out)
      out.rewind()
      val bv = ByteVector.view(out)
      bv
    }
  }

  // def decrypt[A <: CipherAlgorithm](params: CipherParams[A], data: ByteVector): F[ByteVector] = ???
}

private[bobcats] trait CipherPlatform[F[_]] {
  // def importJavaKey(key: crypto.SecretKey): F[SecretKey[CipherAlgorithm]]
}

private[bobcats] trait CipherCompanionPlatform {

  private[bobcats] def forProviders[F[_]](providers: Providers)(
      implicit F: Sync[F]): Cipher[F] = {
    new JavaSecurityCipher(providers)
  }

}

// private[bobcats] trait CipherCompanionPlatform {
//   def forAsync[F[_]: Async]: Cipher[F] = forSync

//   def forSync[F[_]](implicit F: Sync[F]): Cipher[F] =
//     new UnsealedCipher[F] {

//       def generateIv[A <: CipherAlgorithm](algorithm: A): F[IvParameterSpec[A]] =
//         // TODO: We should keep the `SecureRandom` around
//         SecureRandom.javaSecuritySecureRandom[F].flatMap { random =>
//           F.map(random.nextBytes(algorithm.recommendedIvLength)) { ivBytes =>
//             IvParameterSpec(ByteVector.view(ivBytes), algorithm)
//           }
//         }

//       def generateKey[A <: CipherAlgorithm](algorithm: A): F[SecretKey[A]] =
//         F.delay {
//           val keyGen = crypto.KeyGenerator.getInstance(algorithm.toStringJava)
//           keyGen.init(algorithm.keyLength)
//           val key = keyGen.generateKey()
//           SecretKeySpec(ByteVector.view(key.getEncoded()), algorithm)
//         }

//       def importKey[A <: CipherAlgorithm](key: ByteVector, algorithm: A): F[SecretKey[A]] =
//         F.pure(SecretKeySpec(key, algorithm))

//       def importIv[A <: CipherAlgorithm](iv: ByteVector, algorithm: A): F[IvParameterSpec[A]] =
//         F.pure(IvParameterSpec(iv, algorithm))

//       def importJavaKey(key: crypto.SecretKey): F[SecretKey[CipherAlgorithm]] =
//         F.fromOption(
//           for {
//             algorithm <- CipherAlgorithm.fromStringJava(key.getAlgorithm())
//             key <- Option(key.getEncoded())
//           } yield SecretKeySpec(ByteVector.view(key), algorithm),
//           new InvalidKeyException
//         )

//       def encrypt[A <: CipherAlgorithm](
//           key: SecretKey[A],
//           iv: IvParameterSpec[A],
//           data: ByteVector): F[ByteVector] =
//         F.catchNonFatal {
//           val cipher = crypto.Cipher.getInstance(key.algorithm.toModeStringJava)
//           val sk = key.toJava
//           cipher.init(crypto.Cipher.ENCRYPT_MODE, sk, iv.toJava)
//           ByteVector.view(cipher.doFinal(data.toArray))
//         }

//       def decrypt[A <: CipherAlgorithm](
//           key: SecretKey[A],
//           iv: IvParameterSpec[A],
//           data: ByteVector): F[ByteVector] =
//         F.catchNonFatal {
//           val cipher = crypto.Cipher.getInstance(key.algorithm.toModeStringJava)
//           val sk = key.toJava
//           cipher.init(crypto.Cipher.DECRYPT_MODE, sk, iv.toJava)
//           ByteVector.view(cipher.doFinal(data.toArray))
//         }
//     }
// }
