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

import cats.effect.kernel.{Resource, Sync}
import scodec.bits.ByteVector
import scalanative.unsafe._
import scalanative.unsigned._
import openssl._
import openssl.err._
import openssl.evp._
import fs2.{Chunk, Pipe, Stream}

private[bobcats] final class NativeEvpDigest[F[_]](digest: Ptr[EVP_MD])(implicit F: Sync[F])
    extends UnsealedHash1[F] {
  def digest(data: ByteVector): F[ByteVector] = {
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
      F.pure(ByteVector.fromPtr(md.asInstanceOf[Ptr[Byte]], s(0).toLong))
    } catch {
      case e: Error => F.raiseError(e)
    } finally {
      EVP_MD_CTX_free(ctx)
    }
  }

  def pipe: Pipe[F, Byte, Byte] = { in =>
    Stream
      .bracket(F.delay {
        val ctx = EVP_MD_CTX_new()
        if (EVP_DigestInit_ex(ctx, digest, null) != 1) {
          throw Error("EVP_DigestInit_ex", ERR_get_error())
        }
        ctx
      })(ctx => F.delay(EVP_MD_CTX_free(ctx)))
      .flatMap { ctx =>
        in.chunks
          .evalMap { chunk =>
            F.delay {
              val d = chunk.toByteVector.toArrayUnsafe
              val len = d.length
              if (EVP_DigestUpdate(ctx, if (len == 0) null else d.at(0), len.toULong) != 1) {
                throw Error("EVP_DigestUpdate", ERR_get_error())
              }
            }
          }
          .drain ++ Stream.eval {
          F.delay {
            val md = stackalloc[CUnsignedChar](EVP_MAX_MD_SIZE)
            val s = stackalloc[CInt]()

            if (EVP_DigestFinal_ex(ctx, md, s) != 1) {
              throw Error("EVP_DigestFinal_ex", ERR_get_error())
            }
            Chunk.byteVector(ByteVector.fromPtr(md.asInstanceOf[Ptr[Byte]], s(0).toLong))
          }
        }.unchunks
      }
  }
}

private[bobcats] trait Hash1CompanionPlatform {

  private[bobcats] def evpAlgorithm(algorithm: HashAlgorithm): CString = {
    import HashAlgorithm._
    algorithm match {
      case MD5 => c"MD5"
      case SHA1 => c"SHA1"
      case SHA256 => c"SHA256"
      case SHA512 => c"SHA512"
    }
  }

  def fromNameResource[F[_]](name: CString)(implicit F: Sync[F]): Resource[F, Hash1[F]] =
    Resource
      .make(F.delay {
        val md = EVP_MD_fetch(null, name, null)
        md
      })(md => F.delay(EVP_MD_free(md)))
      .map { md => new NativeEvpDigest(md) }

  def forSyncResource[F[_]: Sync](algorithm: HashAlgorithm): Resource[F, Hash1[F]] =
    fromNameResource(evpAlgorithm(algorithm))
}
