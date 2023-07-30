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
import evp._

private[bobcats] trait HashCompanionPlatform {
  implicit def forAsync[F[_]](implicit F: Async[F]): Hash[F] =
    new UnsealedHash[F] {
      override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] =
        F.catchNonFatal {
          Zone { implicit z =>
            val str = toCString(algorithm.toStringNative)
            val digest = EVP_get_digestbyname(str)
            if (digest == null) {
              throw new EvpException("Unknown message digest")
            }
            val ctx = EVP_MD_CTX_new()
            try {
              val d = data.toPtr
              if (EVP_DigestInit_ex(ctx, digest, null) != 1) {
                throw new EvpException("Message digest initialization failed")
              }
              if (EVP_DigestUpdate(ctx, d, data.size.toULong) != 1) {
                throw new EvpException("Message digest update failed")
              }
              val md = stackalloc[CUnsignedChar](EVP_MAX_MD_SIZE)
              val s = stackalloc[CInt](1)
              if (EVP_DigestFinal_ex(ctx, md, s) != 1) {
                throw new EvpException("Message digest finalization failed")
              }
              val bytes = ByteVector.fromPtr(md.asInstanceOf[Ptr[Byte]], s(0).toLong)
              bytes
            } finally {
              EVP_MD_CTX_free(ctx)
            }
          }
        }
    }
}
