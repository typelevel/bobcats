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
import cats.implicits.toFunctorOps
import cats.syntax.all._
import org.scalajs.dom.crypto
import scodec.bits.ByteVector

private[bobcats] trait VerifierPlatform[F[_]]

private[bobcats] trait VerifierCompanionPlatform {
  implicit def forAsync[F[_]](implicit FA: Async[F]): Verifier[F] =
    new UnsealedVerifier[F] {
      override def verify(spec: SPKIKeySpec[_], sig: AsymmetricKeyAlg.Signature)(
          signingStr: ByteVector,
          signature: ByteVector
      ): F[Boolean] =
        // todo: optimise so that key is only calculated once
        for {
          key <- spec.toWebCryptoKey(sig)
          ok <- FA.fromPromise(FA.delay {
            crypto
              .subtle
              .verify( // todo: report to dom that this should really return a Boolean promise
                JSKeySpec.signatureAlgorithm(sig),
                key,
                signature.toJSArrayBuffer,
                signingStr.toJSArrayBuffer
              )
          })
        } yield {
          // see https://github.com/scala-js/scala-js-dom/issues/660
          ok.asInstanceOf[Boolean]
        }
    }
}
