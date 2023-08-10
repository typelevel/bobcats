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
import cats.syntax.all._
import scodec.bits.ByteVector
import fs2.{Pipe, Stream}

private[bobcats] trait HashCompanionPlatform {
  private[bobcats] def forSyncNodeJS[F[_]: Sync]: Hash[F] =
    new UnsealedHash[F] {
      override def digestPipe(algorithm: HashAlgorithm): Pipe[F, Byte, Byte] =
        in =>
          Stream.eval(Hash1.fromJSCryptoName(algorithm.toStringNodeJS)).flatMap { hash =>
            in.through(hash.pipe)
          }

      override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] =
        Hash1.fromJSCryptoName(algorithm.toStringNodeJS).flatMap(_.digest(data))
    }

  private[bobcats] def forAsyncSubtleCrypto[F[_]: Async]: Hash[F] =
    new UnsealedHash[F] {
      override def digestPipe(algorithm: HashAlgorithm): Pipe[F, Byte, Byte] =
        new SubtleCryptoDigest(algorithm.toStringWebCrypto).pipe

      override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] =
        new SubtleCryptoDigest(algorithm.toStringWebCrypto).digest(data)
    }

  def forAsync[F[_]: Async]: Resource[F, Hash[F]] =
    Resource.pure(if (facade.isNodeJSRuntime) forSyncNodeJS else forAsyncSubtleCrypto)
}
