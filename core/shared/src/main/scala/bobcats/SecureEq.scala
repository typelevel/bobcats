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

import cats.kernel.Eq
import scodec.bits.ByteVector

trait SecureEq[A] extends Eq[A]

object SecureEq extends SecureEqCompanionPlatform {

  def apply[A](implicit eq: SecureEq[A]): eq.type = eq

  /**
   * A port of Java's `MessageDigest.isEqual`.
   *
   * All bytes in `digesta` are examined to determine equality. The calculation time depends
   * only on the length of `digesta`. It does not depend on the length of `digestb` or the
   * contents of `digesta` and `digestb`.
   */
  private[bobcats] final class ByteVectorSecureEq extends SecureEq[ByteVector] {
    override def eqv(digesta: ByteVector, digestb: ByteVector): Boolean =
      (digesta eq digestb) || {
        val lenA = digesta.intSize.get
        val lenB = digestb.intSize.get

        if (lenB == 0) {
          lenA == 0
        } else {
          var result = 0
          result |= lenA - lenB

          var i = 0
          // time-constant comparison
          while (i < lenA) {
            val indexB = ((i - lenB) >>> 31) * i
            result |= digesta(i.toLong) ^ digestb(indexB.toLong)
            i += 1
          }
          result == 0

        }
      }

  }

}
