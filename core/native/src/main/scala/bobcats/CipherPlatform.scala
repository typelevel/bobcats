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

  def encrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector] = {

    (key, params) match {
      case (SecretKeySpec(key, gcm: AES.GCM), AES.GCM.Params(iv, tagLength, ad)) =>
        // FIPS_evp_aes_128_gcm
        val name = gcm.keyLength.value match {
          case 128 => c"AES-128-GCM"
          case 192 => c"AES-192-GCM"
          case 256 => c"AES-256-GCM"
          case _ =>
            throw new IllegalArgumentException("here")

            ???
        }

        val cipherCtx = EVP_CIPHER_CTX_new()

        try {

          val cipher = EVP_CIPHER_fetch(ctx, name, null)
          if (cipher == null) {
            throw Error("EVP_CIPHER_fetch", ERR_get_error())
          }

          val uintParams = stackalloc[CUnsignedInt](4)
          val ivArray = iv.data.toArrayUnsafe
          val ivLength = ivArray.length
          // uintParams(0) = 0.toUInt
          uintParams(0) = 64.toUInt
          uintParams(2) = key.size.toUInt
          val params = stackalloc[OSSL_PARAM](5)
          // OSSL_CIPHER_PARAM_PADDING(params(0), uintParams + 1)
          OSSL_CIPHER_PARAM_IVLEN(params(0), uintParams)
          // OSSL_CIPHER_PARAM_KEYLEN(params(2), uintParams + 3)
          OSSL_PARAM_END(params(1))
          if (EVP_CipherInit_ex2(
              cipherCtx,
              cipher,
            null,
            null,
            1,
            null
              // key.toArrayUnsafe.at(0),
              // iv.data.toArrayUnsafe.at(0),
              // 1,
              ) != 1) {
            throw Error("EVP_CipherInit_ex2", ERR_get_error())
          }


          if(EVP_CIPHER_CTX_set_params(cipherCtx, params) != 1) {
            throw Error("EVP_CIPHER_CTX_set_params", ERR_get_error())
          }


          if (EVP_CipherInit_ex2(
              cipherCtx,
              cipher,
              key.toArrayUnsafe.at(0),
              iv.data.toArrayUnsafe.at(0),
              1,
              null) != 1) {
            throw Error("EVP_CipherInit_ex2", ERR_get_error())
          }


          // TODO: no-copy
          val outl = stackalloc[CSize](1)
          val dataArray = data.toArrayUnsafe
          val dataLen = dataArray.length
          val out = new Array[Byte](dataLen + tagLength.byteLength)

          if (EVP_CipherUpdate(
              cipherCtx,
              out.at(0).asInstanceOf[Ptr[CUnsignedChar]],
            outl,
            (if (dataLen > 0)
              dataArray.at(0).asInstanceOf[Ptr[CUnsignedChar]] else null),
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
          OSSL_CIPHER_PARAM_AEAD_TAG(outParams(0), out.at(dataLen), tagLength.byteLength.toULong)
          OSSL_PARAM_END(outParams(1))

          if (EVP_CIPHER_CTX_get_params(
            cipherCtx,
            outParams
              ) != 1) {
            throw Error("EVP_CIPHER_CTX_get_params", ERR_get_error())
          }


          	// EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuf);
          F.pure(ByteVector(out))
        } finally {
          EVP_CIPHER_CTX_free(cipherCtx)
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
