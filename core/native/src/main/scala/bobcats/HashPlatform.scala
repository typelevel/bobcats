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

import scala.scalanative.annotation.alwaysinline
import cats.effect.kernel.{Async, Resource, Sync}
import scodec.bits.ByteVector
import scalanative.unsafe._
import scalanative.unsigned._
import openssl._
import openssl.err._
import openssl.evp._

private final class NativeEvpDigest[F[_]](val ctx: Ptr[EVP_MD_CTX], digest: Ptr[EVP_MD])(
    implicit F: Sync[F])
    extends UnsealedDigest[F] {

  override def update(data: ByteVector): F[Unit] = F.delay {

    val d = data.toArrayUnsafe
    val len = d.length

    if (EVP_DigestUpdate(ctx, if (len == 0) null else d.at(0), d.length.toULong) != 1) {
      throw Error("EVP_DigestUpdate", ERR_get_error())
    }
  }

  override val reset = F.delay {
    if (EVP_MD_CTX_reset(ctx) != 1) {
      throw Error("EVP_MD_Ctx_reset", ERR_get_error())
    }
    if (EVP_DigestInit_ex(ctx, digest, null) != 1) {
      throw Error("EVP_DigestInit_ex", ERR_get_error())
    }
  }

  override def get: F[ByteVector] = F.delay {
    val md = stackalloc[CUnsignedChar](EVP_MAX_MD_SIZE)
    val s = stackalloc[CInt]()

    if (EVP_DigestFinal_ex(ctx, md, s) != 1) {
      throw Error("EVP_DigestFinal_ex", ERR_get_error())
    }
    ByteVector.fromPtr(md.asInstanceOf[Ptr[Byte]], s(0).toLong)
  }

  def free: F[Unit] = F.delay(EVP_MD_CTX_free(ctx))

}

private[bobcats] trait HashCompanionPlatform {
  implicit def forAsync[F[_]](implicit F: Async[F]): Hash[F] = forSync

  private[bobcats] def forSync[F[_]](implicit F: Sync[F]): Hash[F] =
    new UnsealedHash[F] {

      @alwaysinline private def evpAlgorithm(algorithm: HashAlgorithm): Ptr[EVP_MD] = {
        import HashAlgorithm._
        algorithm match {
          case MD5 => EVP_md5()
          case SHA1 => EVP_sha1()
          case SHA256 => EVP_sha256()
          case SHA512 => EVP_sha512()
        }
      }

      override def incremental(algorithm: HashAlgorithm): Resource[F, Digest[F]] = {
        val digest = evpAlgorithm(algorithm)
        Resource.make(F.delay {
          val ctx = EVP_MD_CTX_new()
          if (EVP_DigestInit_ex(ctx, digest, null) != 1) {
            throw Error("EVP_DigestInit_ex", ERR_get_error())
          }
          new NativeEvpDigest(ctx, digest)(F)
        })(_.free)
      }

      override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] = {

        val digest = evpAlgorithm(algorithm)

        F.delay {
          val ctx = EVP_MD_CTX_new()
          val d = data.toArrayUnsafe
          try {
            val md = stackalloc[CUnsignedChar](EVP_MAX_MD_SIZE)
            val s = stackalloc[CInt]()
            if (EVP_DigestInit_ex(ctx, digest, null) != 1) {
              throw Error("EVP_DigestInit_ex", ERR_get_error())
            }
            val len = d.length
            if (EVP_DigestUpdate(ctx, if (len == 0) null else d.at(0), len.toULong) != 1) {
              throw Error("EVP_DigestUpdate", ERR_get_error())
            }
            if (EVP_DigestFinal_ex(ctx, md, s) != 1) {
              throw Error("EVP_DigestFinal_ex", ERR_get_error())
            }
            ByteVector.fromPtr(md.asInstanceOf[Ptr[Byte]], s(0).toLong)
          } finally {
            EVP_MD_CTX_free(ctx)
          }
        }
      }
    }
}
