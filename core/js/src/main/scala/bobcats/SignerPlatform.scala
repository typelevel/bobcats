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
import org.scalajs.dom
import org.scalajs.dom.crypto
import scodec.bits.ByteVector

import scala.scalajs.js

private[bobcats] trait SignerPlatform[F[_]]

private[bobcats] trait SignerCompanionPlatform {
  implicit def forAsync[F[_]](implicit FA: Async[F]): Signer[F] =
    new UnsealedSigner[F] {

      /**
       * Given a Private Key specification and a Signature type, return a function from Byte
       * Vector to signatures
       */
      override def sign(privSpec: PrivateKeySpec[_], sig: AsymmetricKeyAlg.Signature)(
          data: ByteVector
      ): F[ByteVector] = for {
        key <- privSpec.toWebCryptoKey(sig)
        any <- FA.fromPromise(
          FA.delay(
            crypto.subtle.sign(JSKeySpec.signatureAlgorithm(sig), key, data.toJSArrayBuffer)
          ))
      } yield { // see https://github.com/scala-js/scala-js-dom/issues/660
        ByteVector.fromJSArrayBuffer(any.asInstanceOf[js.typedarray.ArrayBuffer])
      }
    }
}
