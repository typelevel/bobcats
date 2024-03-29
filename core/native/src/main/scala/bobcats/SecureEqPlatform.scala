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

import scodec.bits.ByteVector

private[bobcats] trait SecureEqCompanionPlatform { this: SecureEq.type =>

  implicit val secureEqForByteVector: SecureEq[ByteVector] =
    new SecureEq[ByteVector] {

      import scala.scalanative.unsafe._
      import scala.scalanative.unsigned._
      import openssl.crypto._

      override def eqv(x: ByteVector, y: ByteVector): Boolean = {
        val xArr = x.toArrayUnsafe
        val len = xArr.length
        len == y.length && (len == 0 || CRYPTO_memcmp(
          xArr.at(0),
          y.toArrayUnsafe.at(0),
          len.toULong) == 0)
      }
    }

}
