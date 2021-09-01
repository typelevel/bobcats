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

package bobcats.unsafe

import bobcats.facade

import java.util.Random
import scala.scalajs.js
import scodec.bits.ByteVector

final class SecureRandom extends Random {

  private def nextBytes(numBytes: Int): js.typedarray.Uint8Array =
    if (facade.isNodeJSRuntime)
      facade.node.crypto.randomBytes(numBytes)
    else
      facade.browser.crypto.getRandomValues(new js.typedarray.Uint8Array(numBytes))

  override def nextBytes(bytes: Array[Byte]): Unit =
    ByteVector.view(nextBytes(bytes.length)).copyToArray(bytes, 0)

  // Java's SecureRandom overrides this and thus so do we
  override protected final def next(numBits: Int): Int = {
    val numBytes = (numBits + 7) / 8;
    val b = new js.typedarray.Int8Array(nextBytes(numBytes).buffer);
    var next = 0;

    var i = 0
    while (i < numBytes) {
      next = (next << 8) + (b(i) & 0xff)
      i += 1
    }

    next >>> (numBytes * 8 - numBits);
  }

}
