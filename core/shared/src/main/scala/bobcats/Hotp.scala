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
import cats.syntax.functor._
import scodec.bits.ByteVector

sealed trait Hotp[F[_]] extends HotpPlatform[F] {
  def generate(
      key: SecretKey[HmacAlgorithm.SHA1.type],
      movingFactor: Long,
      digits: Int = 6
  ): F[Int]
}

private[bobcats] trait UnsealedHotp[F[_]] extends Hotp[F]

object Hotp extends HotpCompanionPlatform {
  private val powersOfTen =
    Array(1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000)

  def apply[F[_]](implicit hotp: Hotp[F]): hotp.type = hotp

  implicit def forSync[F[_]](implicit F: Sync[F], H: Hmac[F]): Hotp[F] =
    new UnsealedHotp[F] {
      override def generate(
          key: SecretKey[HmacAlgorithm.SHA1.type],
          movingFactor: Long,
          digits: Int
      ): F[Int] = {
        H.digest(key, ByteVector.fromLong(movingFactor)).map { hmac =>
          val offset = hmac.last & 0xf

          val binaryCode = ((hmac.get(offset.longValue) & 0x7f) << 24) |
            ((hmac.get((offset + 1).longValue) & 0xff) << 16) |
            ((hmac.get((offset + 2).longValue) & 0xff) << 8) |
            (hmac.get((offset + 3).longValue) & 0xff)

          binaryCode % powersOfTen(digits)
        }
      }
    }
}
