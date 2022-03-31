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

/*
 * Copyright (c) 2000-2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 */

package bobcats

import cats.kernel.Eq
import scodec.bits.ByteVector

trait SecureEq[A] extends Eq[A] {

  /**
   * A constant time equals comparison - does not terminate early if test will fail. For best
   * results always pass the expected value as the first parameter.
   */
  override def eqv(expected: A, supplied: A): Boolean
}

object SecureEq extends SecureEqCompanionPlatform {

  def apply[A](implicit eq: SecureEq[A]): eq.type = eq

  private[bobcats] final class ByteVectorSecureEq extends SecureEq[ByteVector] {

    override def eqv(expected: ByteVector, supplied: ByteVector): Boolean =
      (expected eq supplied) || {
        val expectedLen = expected.size
        val suppliedLen = supplied.size

        val len = Math.min(expectedLen, suppliedLen)
        var nonEqual = expected.length ^ supplied.length;

        var i = 0L
        while (i != len) {
          nonEqual |= (expected(i) ^ supplied(i))
          i += 1
        }
        i = len
        while (i < suppliedLen) {
          nonEqual |= (supplied(i) ^ ~supplied(i))
          i += 1
        }

        nonEqual == 0
      }

  }

}
