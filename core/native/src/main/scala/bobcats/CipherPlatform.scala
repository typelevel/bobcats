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
import scala.scalanative.annotation.alwaysinline

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
      padding: Boolean,
      mode: Int
  ): Unit = {
    val ivLength = iv.length
    val uintParams = stackalloc[CUnsignedInt](2)
    uintParams(0) = ivLength.toUInt
    uintParams(1) = (if (padding) 1 else 0).toUInt

    val params = stackalloc[OSSL_PARAM](3)
    OSSL_CIPHER_PARAM_IVLEN(params(0), uintParams)
    OSSL_CIPHER_PARAM_PADDING(params(1), uintParams + 1)
    OSSL_PARAM_END(params(2))

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

  private def updateAD(ctx: Ptr[EVP_CIPHER_CTX], ad: ByteVector): Unit = {
    val arr = ad.toArrayUnsafe
    val len = arr.length
    val outl = stackalloc[CSize](1)

    if (EVP_CipherUpdate(
        ctx,
        null,
        outl,
        if (len > 0) arr.at(0).asInstanceOf[Ptr[CUnsignedChar]]
        else null,
        len.toULong
      ) != 1) {
      throw Error("EVP_CipherUpdate", ERR_get_error())
    }
  }

  private def updateFinal(
      ctx: Ptr[EVP_CIPHER_CTX],
      out: Array[Byte],
      outl: Ptr[CSize],
      data: Array[Byte],
      dataLen: Int) {
    if (EVP_CipherUpdate(
        ctx,
        out.at(0).asInstanceOf[Ptr[CUnsignedChar]],
        outl,
        if (dataLen > 0)
          data.at(0).asInstanceOf[Ptr[CUnsignedChar]]
        else null,
        dataLen.toULong
      ) != 1) {
      throw Error("EVP_CipherUpdate", ERR_get_error())
    }

    // TODO: Remove when `atUnsafe` comes around
    val ptr = if (outl(0).toInt >= out.size) {
      null
    } else {
      out.at(outl(0).toInt).asInstanceOf[Ptr[CUnsignedChar]]
    }

    if (EVP_CipherFinal(ctx, ptr, outl) != 1) {
      throw Error("EVP_CipherFinal", ERR_get_error())
    }
  }

  @alwaysinline private def cipherFetch[A](name: CString)(f: Ptr[EVP_CIPHER] => F[A]): F[A] = {
    val cipher = EVP_CIPHER_fetch(ctx, name, null)
    if (cipher == null) {
      EVP_CIPHER_free(cipher)
      F.raiseError(
        new NoSuchAlgorithmException(null, Error("EVP_CIPHER_fetch", ERR_get_error())))
    } else {
      f(cipher)
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
        cipherFetch(name) { cipher =>
          val cipherCtx = EVP_CIPHER_CTX_new()
          try {

            initKeyIv(cipherCtx, cipher, key.toArrayUnsafe, iv.data.toArrayUnsafe, false, 1)
            updateAD(cipherCtx, ad)

            val outl = stackalloc[CSize](1)
            val dataArray = data.toArrayUnsafe
            val dataLen = dataArray.length
            val out = new Array[Byte](dataArray.length + tagLength.byteLength)

            updateFinal(cipherCtx, out, outl, dataArray, dataLen)

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
          } catch {
            case e: Error => F.raiseError(e)
          } finally {
            EVP_CIPHER_CTX_free(cipherCtx)
            EVP_CIPHER_free(cipher)
          }

        }
      case (SecretKeySpec(key, cbc: AES.CBC), AES.CBC.Params(iv)) =>
        val keyLength = cbc.keyLength.value
        val name = keyLength match {
          case 256 => c"AES-256-CBC"
          case _ => ???
        }
        cipherFetch(name) { cipher =>
          val cipherCtx = EVP_CIPHER_CTX_new()
          try {

            initKeyIv(cipherCtx, cipher, key.toArrayUnsafe, iv.data.toArrayUnsafe, false, 1)
            val outl = stackalloc[CSize](1)
            val dataArray = data.toArrayUnsafe
            val dataLen = dataArray.length
            val out = new Array[Byte](dataArray.length)
            updateFinal(cipherCtx, out, outl, dataArray, dataLen)
            F.pure(ByteVector(out))
          } catch {
            case e: Error => F.raiseError(e)
          } finally {
            EVP_CIPHER_CTX_free(cipherCtx)
            EVP_CIPHER_free(cipher)
          }

        }
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
