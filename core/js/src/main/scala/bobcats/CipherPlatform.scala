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

import cats.effect.kernel.{Async, Sync}
import scodec.bits.ByteVector
import cats.syntax.all._

import scala.scalajs.js

private[bobcats] trait CipherPlatform[F[_]]

private final class SubtleCryptoCipher[F[_]](implicit F: Async[F]) extends UnsealedCipher[F] {

  import facade.browser.{crypto, AesGcmParams, AesImportParams}
  import BlockCipherAlgorithm._

  override def importKey[A <: CipherAlgorithm[_]](
      key: ByteVector,
      algorithm: A): F[SecretKey[A]] =
    F.pure(SecretKeySpec(key, algorithm))

  override def encrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector] =
    key match {
      case SecretKeySpec(key, algorithm) =>
        (algorithm, params) match {
          case (gcm: AES.GCM, AES.GCM.Params(iv, padding, tagLength, ad)) =>
            for {
              key <- F.fromPromise(
                F.delay(
                  crypto
                    .subtle
                    .importKey(
                      "raw",
                      key.toUint8Array,
                      new AesImportParams {
                        val name = "AES-GCM"
                      },
                      false,
                      js.Array("encrypt"))))
              cipherText <- F.fromPromise(
                F.delay(
                  crypto
                    .subtle
                    .encrypt(
                      AesGcmParams(
                        iv.data.toJSArrayBuffer,
                        if (ad.isEmpty) js.undefined else ad.toUint8Array),
                      key,
                      data.toJSArrayBuffer)))

            } yield ByteVector.view(cipherText)
        }
    }

  def decrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector] = ???

}

private final class CryptoCipher[F[_]](ciphers: js.Array[String])(implicit F: Sync[F])
    extends UnsealedCipher[F] {

  import facade.node.crypto
  import facade.node.CipherOptions

  import BlockCipherAlgorithm._

  def importKey[A <: CipherAlgorithm[_]](key: ByteVector, algorithm: A): F[SecretKey[A]] =
    F.pure(SecretKeySpec(key, algorithm))

  // TODO: Macro
  private def aesGcmName(keyLength: AES.KeyLength): String =
    keyLength.value match {
      case 128 => "aes-128-gcm"
      case 192 => "aes-192-gcm"
      case 256 => "aes-256-gcm"
    }

  private def aesCbcName(keyLength: AES.KeyLength): String =
    keyLength.value match {
      case 128 => "aes-128-cbc"
      case 192 => "aes-192-cbc"
      case 256 => "aes-256-cbc"
    }

  override def encrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector] = {
    key match {
      case SecretKeySpec(key, algorithm) =>
        try {
          val bytes = (algorithm, params) match {
            case (gcm: AES.GCM, AES.GCM.Params(iv, padding, tagLength, ad)) =>
              val name = aesGcmName(gcm.keyLength)
              if (!ciphers.contains(name)) {
                throw new MissingAlgorithm(algorithm)
              }
              val cipher = crypto
                .createCipheriv(
                  name,
                  key.toUint8Array,
                  iv.data.toUint8Array,
                  new CipherOptions {
                    val authTagLength = tagLength.byteLength
                  }
                )
                .setAutoPadding(padding)
                .setAAD(ad.toUint8Array)
              val cipherText = cipher.update(data.toUint8Array)
              ByteVector.view(cipherText) ++ ByteVector.view(cipher.`final`()) ++ ByteVector
                .view(cipher.getAuthTag())
            case (cbc: AES.CBC, AES.CBC.Params(iv, padding)) =>
              val name = aesCbcName(cbc.keyLength)
              if (!ciphers.contains(name)) {
                throw new MissingAlgorithm(cbc)
              }
              val cipher = crypto
                .createCipheriv(
                  name,
                  key.toUint8Array,
                  iv.data.toUint8Array
                )
                .setAutoPadding(padding)
              val cipherText = cipher.update(data.toUint8Array)
              ByteVector.view(cipherText) ++ ByteVector.view(cipher.`final`())
          }
          F.pure(bytes)
        } catch {
          case e: GeneralSecurityException => F.raiseError(e)
        }
    }
  }

  def decrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector] = ???
}

private[bobcats] trait CipherCompanionPlatform {

  private[bobcats] def forCryptoCiphers[F[_]: Sync](ciphers: js.Array[String]): Cipher[F] =
    new CryptoCipher(ciphers)

  private[bobcats] def forSubtleCrypto[F[_]: Async]: Cipher[F] = new SubtleCryptoCipher

}
