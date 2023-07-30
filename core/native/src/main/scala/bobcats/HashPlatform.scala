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
import scodec.bits.ByteVector
import scalanative.unsafe._
import scalanative.unsigned._
import openssl._
import openssl.err._
import openssl.evp._

private[bobcats] trait HashCompanionPlatform {
  implicit def forAsync[F[_]](implicit F: Async[F]): Hash[F] =
    new UnsealedHash[F] {
      override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] = {

        import HashAlgorithm._

        val digest = algorithm match {
          case MD5 => EVP_md5()
          case SHA1 => EVP_sha1()
          case SHA256 => EVP_sha256()
          case SHA512 => EVP_sha512()
        }

        F.defer {
          Zone { implicit z =>
            val ctx = EVP_MD_CTX_new()
            val d = data.toPtr
            try {
              val md = stackalloc[CUnsignedChar](EVP_MAX_MD_SIZE)
              val s = stackalloc[CInt]()
              if (EVP_DigestInit_ex(ctx, digest, null) != 1) {
                throw Error("EVP_DigestInit_ex", ERR_get_error())
              }
              if (EVP_DigestUpdate(ctx, d, data.size.toULong) != 1) {
                throw Error("EVP_DigestUpdate", ERR_get_error())
              }
              if (EVP_DigestFinal_ex(ctx, md, s) != 1) {
                throw Error("EVP_DigestFinal_ex", ERR_get_error())
              }
              val bytes = ByteVector.fromPtr(md.asInstanceOf[Ptr[Byte]], s(0).toLong)
              F.pure(bytes)
            } catch {
              case e: Error => F.raiseError[ByteVector](e)
            } finally {
              EVP_MD_CTX_free(ctx)
            }
          }
        }
      }
    }
}
