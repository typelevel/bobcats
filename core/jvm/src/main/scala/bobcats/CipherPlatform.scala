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

import cats.effect.kernel.Async
import scodec.bits.ByteVector
import javax.crypto
import cats.effect.std.Random

private[bobcats] trait CipherPlatform[F[_]] {
  def importJavaKey(key: crypto.SecretKey): F[SecretKey[CipherAlgorithm]]
}

private[bobcats] trait CipherCompanionPlatform {
  implicit def forAsync[F[_]](implicit F: Async[F]): Cipher[F] =
    new UnsealedCipher[F] {

      def generateIv[A <: CipherAlgorithm](algorithm: A): F[IvParameterSpec[A]] =
        F.flatMap(Random.javaSecuritySecureRandom[F]) { random =>
          F.map(random.nextBytes(algorithm.recommendedIvLength)) { ivBytes =>
            IvParameterSpec(ByteVector.view(ivBytes), algorithm)
          }
        }

      def generateKey[A <: CipherAlgorithm](algorithm: A): F[SecretKey[A]] =
        F.delay {
          val keyGen = crypto.KeyGenerator.getInstance(algorithm.toStringJava)
          keyGen.init(algorithm.keyLength)
          val key = keyGen.generateKey()
          SecretKeySpec(ByteVector.view(key.getEncoded()), algorithm)
        }

      def importKey[A <: CipherAlgorithm](key: ByteVector, algorithm: A): F[SecretKey[A]] =
        F.pure(SecretKeySpec(key, algorithm))

      def importIv[A <: CipherAlgorithm](iv: ByteVector, algorithm: A): F[IvParameterSpec[A]] =
        F.pure(IvParameterSpec(iv, algorithm))

      def importJavaKey(key: crypto.SecretKey): F[SecretKey[CipherAlgorithm]] =
        F.fromOption(
          for {
            algorithm <- CipherAlgorithm.fromStringJava(key.getAlgorithm())
            key <- Option(key.getEncoded())
          } yield SecretKeySpec(ByteVector.view(key), algorithm),
          new InvalidKeyException
        )

      def encrypt[A <: CipherAlgorithm](
          key: SecretKey[A],
          iv: IvParameterSpec[A],
          data: ByteVector): F[ByteVector] =
        F.catchNonFatal {
          val cipher = crypto.Cipher.getInstance(key.algorithm.toModeStringJava)
          val sk = key.toJava
          cipher.init(crypto.Cipher.ENCRYPT_MODE, sk, iv.toJava)
          ByteVector.view(cipher.doFinal(data.toArray))
        }

      def decrypt[A <: CipherAlgorithm](
          key: SecretKey[A],
          iv: IvParameterSpec[A],
          data: ByteVector): F[ByteVector] =
        F.catchNonFatal {
          val cipher = crypto.Cipher.getInstance(key.algorithm.toModeStringJava)
          val sk = key.toJava
          cipher.init(crypto.Cipher.DECRYPT_MODE, sk, iv.toJava)
          ByteVector.view(cipher.doFinal(data.toArray))
        }
    }
}
