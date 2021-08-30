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

import scala.scalajs.js

private[bobcats] trait HmacCompanionPlatform {
  val SHA1 = if (facade.isNodeJSRuntime) "sha1" else "SHA-1"
  val SHA256 = if (facade.isNodeJSRuntime) "sha256" else "SHA-256"
  val SHA512 = if (facade.isNodeJSRuntime) "sha512" else "SHA-512"

  implicit def forAsync[F[_]](implicit F: Async[F]): Hmac[F] =
    if (facade.isNodeJSRuntime)
      new Hmac[F] {
        override def digest(
            algorithm: String,
            key: ByteVector,
            data: ByteVector): F[ByteVector] =
          F.catchNonFatal {
            val hmac = facade.node.crypto.createHmac(algorithm, key.toUint8Array)
            hmac.update(data.toUint8Array)
            ByteVector.view(hmac.digest())
          }
      }
    else
      new Hmac[F] {
        import bobcats.facade.browser._
        override def digest(
            algorithm: String,
            key: ByteVector,
            data: ByteVector): F[ByteVector] =
          for {
            key <- F.fromPromise(
              F.delay(
                crypto
                  .subtle
                  .importKey(
                    "raw",
                    key.toUint8Array,
                    HmacImportParams(algorithm),
                    false,
                    js.Array("sign"))))
            signature <- F.fromPromise(
              F.delay(crypto.subtle.sign("HMAC", key, data.toUint8Array.buffer)))
          } yield ByteVector.view(signature)
      }
}
