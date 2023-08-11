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
import fs2.{Chunk, Pipe, Stream}

private[bobcats] final class NativeEvpDigest[F[_]](digest: Ptr[EVP_MD])(implicit F: Sync[F])
    extends UnsealedHash1[F] {
  def digest(data: ByteVector): F[ByteVector] = {
    val d = data.toArrayUnsafe
    val ctx = EVP_MD_CTX_new()
    try {
      init(ctx, digest)
      update(ctx, d)
      F.pure(`final`(ctx, (ptr, len) => ByteVector.fromPtr(ptr, len.toLong)))
    } catch {
      case e: Error => F.raiseError(e)
    } finally {
      EVP_MD_CTX_free(ctx)
    }
  }

  private def update(ctx: Ptr[EVP_MD_CTX], data: Array[Byte]): Unit = {
    val len = data.length
    if (EVP_DigestUpdate(ctx, if (len == 0) null else data.at(0), len.toULong) != 1) {
      throw Error("EVP_DigestUpdate", ERR_get_error())
    }
  }

  private def init(ctx: Ptr[EVP_MD_CTX], digest: Ptr[EVP_MD]): Unit =
    if (EVP_DigestInit_ex(ctx, digest, null) != 1) {
      throw Error("EVP_DigestInit_ex", ERR_get_error())
    }

  @alwaysinline private def `final`[A](ctx: Ptr[EVP_MD_CTX], f: (Ptr[Byte], Int) => A): A = {
    val md = stackalloc[CUnsignedChar](EVP_MAX_MD_SIZE)
    val s = stackalloc[CInt]()
    if (EVP_DigestFinal_ex(ctx, md, s) != 1) {
      throw Error("EVP_DigestFinal_ex", ERR_get_error())
    }
    f(md.asInstanceOf[Ptr[Byte]], s(0))
  }

  private val context: Stream[F, Ptr[EVP_MD_CTX]] =
    Stream.bracket(F.delay {
      val ctx = EVP_MD_CTX_new()
      init(ctx, digest)
      ctx
    })(ctx => F.delay(EVP_MD_CTX_free(ctx)))

  def pipe: Pipe[F, Byte, Byte] = { in =>
    context.flatMap { ctx =>
      // Most of the calls throw, so wrap in a `delay`
      in.chunks
        .evalMap { chunk => F.delay(update(ctx, chunk.toByteVector.toArrayUnsafe)) }
        .drain ++ Stream.eval(F.delay(`final`(ctx, Chunk.fromBytePtr)))
    }.unchunks
  }
}

import java.security.NoSuchAlgorithmException

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

  private[bobcats] def evpFetch(ctx: Ptr[OSSL_LIB_CTX], name: CString): Ptr[EVP_MD] = {
    val md = EVP_MD_fetch(ctx, name, null)
    if (md == null) {
      throw new NoSuchAlgorithmException(
        s"${fromCString(name)} Message Digest not available",
        Error("EVP_MD_fetch", ERR_get_error())
      )
    }
    md
  }

  /**
   * Create a hash for a particular name used by `libcrypto`.
   */
  def fromCryptoName[F[_]](name: CString)(implicit F: Sync[F]): Resource[F, Hash1[F]] =
    Resource
      .make(F.delay(evpFetch(null, name)))(md => F.delay(EVP_MD_free(md)))
      .map(new NativeEvpDigest(_))

  def forSync[F[_]: Sync](algorithm: HashAlgorithm): Resource[F, Hash1[F]] =
    fromCryptoName(evpAlgorithm(algorithm))

  def forAsync[F[_]: Async](algorithm: HashAlgorithm): Resource[F, Hash1[F]] = forSync(
    algorithm)
}
