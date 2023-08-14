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

import cats.syntax.all._
import cats.effect.{Async, Resource, Sync}
import scodec.bits.ByteVector
import fs2.{Chunk, Pipe, Stream}

import scala.scalanative.unsafe._

import openssl._
import openssl.evp._
import openssl.params._
import openssl.err._
import scala.scalanative.unsigned._

private final class EvpCipher[F[_]](ctx: Ptr[OSSL_LIB_CTX])(implicit F: Sync[F])
    extends UnsealedCipher[F] {

  def importKey[A <: CipherAlgorithm[_]](key: ByteVector, algorithm: A): F[SecretKey[A]] =
    F.pure(SecretKeySpec(key, algorithm))

  import BlockCipherAlgorithm._

  private def initKeyIv(
      ctx: Ptr[EVP_CIPHER_CTX],
      cipher: Ptr[EVP_CIPHER],
      key: Array[Byte],
      iv: Array[Byte],
      mode: Int
  ): Unit = {
    val ivLength = iv.length
    val ivLen = stackalloc[CUnsignedInt](1)
    ivLen(0) = ivLength.toUInt

    val params = stackalloc[OSSL_PARAM](3)
    OSSL_CIPHER_PARAM_IVLEN(params(0), ivLen)
    OSSL_PARAM_END(params(1))

    // Note: For OpenSSL 3.0.x and below, we /must/ separate out the init calls. See #19822
    if (EVP_CipherInit_ex2(
        ctx,
        cipher,
        null,
        null,
        mode,
        params
      ) != 1) {
      throw Error("EVP_CipherInit_ex2", ERR_get_error())
    }

    if (EVP_CipherInit_ex2(ctx, null, key.at(0), iv.at(0), mode, null) != 1) {
      throw Error("EVP_CipherInit_ex2", ERR_get_error())
    }

  }

  def encrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector] = {

    (key, params) match {
      case (SecretKeySpec(key, gcm: AES.GCM), AES.GCM.Params(iv, tagLength, ad)) =>
        val keyLength = gcm.keyLength.value
        val name = keyLength match {
          case 128 => c"AES-128-GCM"
          case 192 => c"AES-192-GCM"
          case 256 => c"AES-256-GCM"
          case _ => ???
        }
        val cipher = EVP_CIPHER_fetch(ctx, name, null)
        if (cipher == null) {
          EVP_CIPHER_free(cipher)
          F.raiseError(
            new NoSuchAlgorithmException(null, Error("EVP_CIPHER_fetch", ERR_get_error())))
        } else {
          val cipherCtx = EVP_CIPHER_CTX_new()
          try {

            initKeyIv(cipherCtx, cipher, key.toArrayUnsafe, iv.data.toArrayUnsafe, 1)

            val outl = stackalloc[CSize](1)
            val dataArray = data.toArrayUnsafe
            val dataLen = dataArray.length
            val out = new Array[Byte](dataLen + tagLength.byteLength)

            val adArray = ad.toArrayUnsafe
            if (EVP_CipherUpdate(
                cipherCtx,
                null,
                outl,
                if (adArray.length > 0) adArray.at(0).asInstanceOf[Ptr[CUnsignedChar]]
                else null,
                adArray.length.toULong
              ) != 1) {
              throw Error("EVP_CipherUpdate", ERR_get_error())
            }

            if (EVP_CipherUpdate(
                cipherCtx,
                out.at(0).asInstanceOf[Ptr[CUnsignedChar]],
                outl,
                if (dataLen > 0)
                  dataArray.at(0).asInstanceOf[Ptr[CUnsignedChar]]
                else null,
                dataLen.toULong
              ) != 1) {
              throw Error("EVP_CipherUpdate", ERR_get_error())
            }

            if (EVP_CipherFinal(
                cipherCtx,
                out.at(outl(0).toInt).asInstanceOf[Ptr[CUnsignedChar]],
                outl) != 1) {
              throw Error("EVP_CipherFinal", ERR_get_error())
            }

            val outParams = stackalloc[OSSL_PARAM](2)
            OSSL_CIPHER_PARAM_AEAD_TAG(
              outParams(0),
              out.at(dataLen),
              tagLength.byteLength.toULong)
            OSSL_PARAM_END(outParams(1))

            if (EVP_CIPHER_CTX_get_params(
                cipherCtx,
                outParams
              ) != 1) {
              throw Error("EVP_CIPHER_CTX_get_params", ERR_get_error())
            }

            F.pure(ByteVector(out))
          } finally {
            EVP_CIPHER_CTX_free(cipherCtx)
            EVP_CIPHER_free(cipher)
          }
        }

      case _ => ???
    }
  }

  def decrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector] = ???

}

trait CipherPlatform[F[_]] {}

trait CipherCompanionPlatform {
  private[bobcats] def forContext[F[_]](ctx: Ptr[OSSL_LIB_CTX])(
      implicit F: Sync[F]): Cipher[F] = new EvpCipher(ctx)
}
