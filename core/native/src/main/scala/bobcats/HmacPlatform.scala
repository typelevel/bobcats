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

import cats.effect.kernel.{Async, Resource, Sync}
import scodec.bits.ByteVector

private[bobcats] trait HmacPlatform[F[_]] {}

import scala.scalanative.unsafe._

import openssl._
import openssl.evp._
import openssl.params._
import openssl.err._
import scala.scalanative.libc._
import scala.scalanative.unsigned._

private[bobcats] trait HmacCompanionPlatform {

  def forAsync[F[_]: Async]: Resource[F, Hmac[F]] = forSync
  def forSync[F[_]: Sync]: Resource[F, Hmac[F]] = Context[F].map(forContext[F])

  private[bobcats] def forContext[F[_]](ctx: Ptr[OSSL_LIB_CTX])(implicit F: Sync[F]): Hmac[F] =
    new UnsealedHmac[F] {

      /**
       * See [[https://www.openssl.org/docs/man3.1/man7/EVP_MAC-HMAC.html]]
       */
      override def digest(key: SecretKey[HmacAlgorithm], data: ByteVector): F[ByteVector] = {
        key match {
          case SecretKeySpec(key, algorithm) =>
            val mdName = Hash1.evpAlgorithm(algorithm.hashAlgorithm)
            val mdLen = string.strlen(mdName)
            F.catchNonFatal {
              val oneshot = stackalloc[CInt]()
              oneshot(0) = 1
              val params = stackalloc[OSSL_PARAM](3)
              OSSL_MAC_PARAM_DIGEST(params(0), mdName, mdLen)
              OSSL_MAC_PARAM_DIGEST_ONESHOT(params(1), oneshot)
              OSSL_PARAM_END(params(2))
              val mac = EVP_MAC_fetch(ctx, c"HMAC", null)

              if (mac == null) {
                throw Error("EVP_MAC_fetch", ERR_get_error())
              } else {
                val ctx = EVP_MAC_CTX_new(mac)
                try {
                  val k = key.toArrayUnsafe
                  val d = data.toArrayUnsafe
                  if (EVP_MAC_init(
                      ctx,
                      k.at(0).asInstanceOf[Ptr[CUnsignedChar]],
                      k.length.toULong,
                      params
                    ) != 1) {
                    throw Error("EVP_MAC_init", ERR_get_error())
                  }
                  val out = stackalloc[CUnsignedChar](EVP_MAX_MD_SIZE)
                  val outl = stackalloc[CSize]()

                  if (EVP_MAC_update(
                      ctx,
                      d.at(0).asInstanceOf[Ptr[CUnsignedChar]],
                      d.length.toULong) != 1) {
                    throw Error("EVP_MAC_update", ERR_get_error())
                  }

                  if (EVP_MAC_final(ctx, out, outl, EVP_MAX_MD_SIZE.toULong) != 1) {
                    throw Error("EVP_MAC_final", ERR_get_error())
                  }
                  ByteVector.fromPtr(out.asInstanceOf[Ptr[Byte]], outl(0).toLong)
                } finally {
                  EVP_MAC_CTX_free(ctx)
                }
              }
            }
          case _ => F.raiseError[ByteVector](new InvalidKeyException)
        }
      }

      /**
       * See [[https://www.openssl.org/docs/man3.0/man7/EVP_RAND-CTR-DRBG.html]]
       */
      override def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]] = {
        F.delay {
          // See NIST SP 800-90A
          val rand = EVP_RAND_fetch(null, c"CTR-DRBG", null)
          if (rand == null) {
            throw Error("EVP_RAND_fetch", ERR_get_error())
          } else {
            val ctx = EVP_RAND_CTX_new(rand, null)
            val params = stackalloc[OSSL_PARAM](2)
            val out = stackalloc[CUnsignedChar](EVP_MAX_MD_SIZE)
            val cipher = c"AES-256-CTR"

            OSSL_DBRG_PARAM_CIPHER(params(0), cipher, string.strlen(cipher))
            OSSL_PARAM_END(params(1))
            try {

              val strength = 128.toUInt
              val len = algorithm.minimumKeyLength

              if (EVP_RAND_instantiate(ctx, strength, 0, null, 0.toULong, params) != 1) {
                throw Error("EVP_RAND_instantiate", ERR_get_error())
              }
              if (EVP_RAND_generate(ctx, out, len.toULong, strength, 0, null, 0.toULong) != 1) {
                throw Error("EVP_RAND_generate", ERR_get_error())
              }
              val key = ByteVector.fromPtr(out.asInstanceOf[Ptr[Byte]], len.toLong)
              SecretKeySpec(key, algorithm)
            } finally {
              EVP_RAND_CTX_free(ctx)
            }
          }
        }
      }

      override def importKey[A <: HmacAlgorithm](
          key: ByteVector,
          algorithm: A): F[SecretKey[A]] = F.pure(SecretKeySpec(key, algorithm))
    }
}
