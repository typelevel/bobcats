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
import java.lang

private[bobcats] trait HmacPlatform[F[_]]

private[bobcats] trait HmacCompanionPlatform {
  private[bobcats] def forAsyncNodeJS[F[_]](implicit F: Async[F]): Hmac[F] =
    new UnsealedHmac[F] {
      import facade.node._
      override def digest(key: SecretKey[HmacAlgorithm], data: ByteVector): F[ByteVector] =
        key match {
          case SecretKeySpec(key, algorithm) =>
            F.catchNonFatal {
              val hmac = crypto.createHmac(algorithm.toStringNodeJS, key.toUint8Array)
              hmac.update(data.toUint8Array)
              ByteVector.view(hmac.digest())
            }
          case _ => F.raiseError(new InvalidKeyException)
        }

      override def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]] =
        F.async_[SecretKey[A]] { cb =>
          crypto.generateKey(
            "hmac",
            GenerateKeyOptions(algorithm.minimumKeyLength * lang.Byte.SIZE),
            (err, key) =>
              cb(
                Option(err)
                  .map(js.JavaScriptException)
                  .toLeft(SecretKeySpec(ByteVector.view(key.`export`()), algorithm)))
          )
        }

      override def importKey[A <: HmacAlgorithm](
          key: ByteVector,
          algorithm: A): F[SecretKey[A]] =
        F.pure(SecretKeySpec(key, algorithm))
    }

  private[bobcats] def forAsyncSubtleCrypto[F[_]](implicit F: Async[F]): Hmac[F] =
    new UnsealedHmac[F] {
      import bobcats.facade.browser._
      override def digest(key: SecretKey[HmacAlgorithm], data: ByteVector): F[ByteVector] =
        key match {
          case SecretKeySpec(key, algorithm) =>
            for {
              key <- F.fromPromise(
                F.delay(
                  crypto
                    .subtle
                    .importKey(
                      "raw",
                      key.toUint8Array,
                      HmacImportParams(algorithm.toStringWebCrypto),
                      false,
                      js.Array("sign"))))
              signature <- F.fromPromise(
                F.delay(crypto.subtle.sign("HMAC", key, data.toUint8Array.buffer)))
            } yield ByteVector.view(signature)
          case _ => F.raiseError(new InvalidKeyException)
        }

      override def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]] =
        for {
          key <- F.fromPromise(
            F.delay(
              crypto
                .subtle
                .generateKey(
                  HmacKeyGenParams(algorithm.toStringWebCrypto),
                  true,
                  js.Array("sign"))))
          exported <- F.fromPromise(F.delay(crypto.subtle.exportKey("raw", key)))
        } yield SecretKeySpec(ByteVector.view(exported), algorithm)

      override def importKey[A <: HmacAlgorithm](
          key: ByteVector,
          algorithm: A): F[SecretKey[A]] =
        F.pure(SecretKeySpec(key, algorithm))
    }
}
