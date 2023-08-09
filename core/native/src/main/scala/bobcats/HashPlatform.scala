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

import cats.effect.kernel.Sync
import scodec.bits.ByteVector
import scalanative.unsafe._
import openssl._
import openssl.evp._
import fs2.{Pipe, Stream}

private[bobcats] trait HashCompanionPlatform {

  private[bobcats] def forContext[F[_]](ctx: Ptr[OSSL_LIB_CTX])(implicit F: Sync[F]): Hash[F] =
    new UnsealedHash[F] {

      override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] = {
        val md = EVP_MD_fetch(ctx, Hash1.evpAlgorithm(algorithm), null)
        // Note, this is eager currently which is why the cleanup is working
        val digest = new NativeEvpDigest(md).digest(data)
        EVP_MD_free(md)
        digest
      }

      override def digestPipe(algorithm: HashAlgorithm): Pipe[F, Byte, Byte] =
        in => {
          Stream
            .bracket(F.delay {
              EVP_MD_fetch(null, Hash1.evpAlgorithm(algorithm), null)
            })(md => F.delay(EVP_MD_free(md)))
            .flatMap { md => in.through(new NativeEvpDigest(md).pipe) }
        }
    }
}
