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
import cats.syntax.all._
import scodec.bits.ByteVector

private[bobcats] trait HashCompanionPlatform {
  implicit def forAsync[F[_]](implicit F: Async[F]): Hash[F] =
    if (facade.isNodeJSRuntime)
      new Hash[F] {
        override def digest(algorithm: String, data: ByteVector): F[ByteVector] =
          F.catchNonFatal {
            val hash = facade.node.crypto.createHash(algorithm)
            hash.update(data.toUint8Array)
            ByteVector.view(hash.digest())
          }
      }
    else
      new Hash[F] {
        override def digest(algorithm: String, data: ByteVector): F[ByteVector] =
          F.fromPromise(
            F.delay(facade.browser.crypto.subtle.digest(algorithm, data.toUint8Array.buffer)))
            .map(ByteVector.view)
      }
}
