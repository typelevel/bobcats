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

import cats.effect.kernel.Sync
import scodec.bits.ByteVector
import javax.crypto

private[bobcats] trait HmacPlatform[F[_]] {
  def importJavaKey(key: crypto.SecretKey): F[SecretKey[HmacAlgorithm]]
}

private[bobcats] trait HmacCompanionPlatform {
  implicit def forSync[F[_]](implicit F: Sync[F]): Hmac[F] =
    new UnsealedHmac[F] {

      override def digest(key: SecretKey[HmacAlgorithm], data: ByteVector): F[ByteVector] =
        F.catchNonFatal {
          val mac = crypto.Mac.getInstance(key.algorithm.toStringJava)
          val sk = key.toJava
          mac.init(sk)
          mac.update(data.toByteBuffer)
          ByteVector.view(mac.doFinal())
        }

      override def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]] =
        F.delay {
          val key = crypto.KeyGenerator.getInstance(algorithm.toStringJava).generateKey()
          SecretKeySpec(ByteVector.view(key.getEncoded()), algorithm)
        }

      override def importKey[A <: HmacAlgorithm](
          key: ByteVector,
          algorithm: A): F[SecretKey[A]] =
        F.pure(SecretKeySpec(key, algorithm))

      override def importJavaKey(key: crypto.SecretKey): F[SecretKey[HmacAlgorithm]] =
        F.fromOption(
          for {
            algorithm <- HmacAlgorithm.fromStringJava(key.getAlgorithm())
            key <- Option(key.getEncoded())
          } yield SecretKeySpec(ByteVector.view(key), algorithm),
          new InvalidKeyException
        )
    }
}
