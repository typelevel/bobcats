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

private final class NodeCryptoDigest[F[_]](var hash: facade.node.Hash, algorithm: String)(
    implicit F: Sync[F])
    extends UnsealedDigest[F] {
  override def update(data: ByteVector): F[Unit] = F.delay(hash.update(data.toUint8Array))
  override val reset = F.delay {
    hash = facade.node.crypto.createHash(algorithm)
  }
  override def get: F[ByteVector] = F.delay(ByteVector.view(hash.digest()))
}

private[bobcats] trait HashCompanionPlatform {
  implicit def forAsync[F[_]](implicit F: Async[F]): Hash[F] =
    if (facade.isNodeJSRuntime)
      new UnsealedHash[F] {

        override def incremental(algorithm: HashAlgorithm): Resource[F, Digest[F]] =
          Resource.make(F.catchNonFatal {
            val alg = algorithm.toStringNodeJS
            val hash = facade.node.crypto.createHash(alg)
            new NodeCryptoDigest(hash, alg)
          })(_ => F.unit)
        override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] =
          F.catchNonFatal {
            val hash = facade.node.crypto.createHash(algorithm.toStringNodeJS)
            hash.update(data.toUint8Array)
            ByteVector.view(hash.digest())
          }
      }
    else
      new UnsealedHash[F] {
        import facade.browser._
        override def incremental(algorithm: HashAlgorithm): Resource[F, Digest[F]] = {
          val err = F.raiseError[Digest[F]](
            new UnsupportedOperationException("WebCrypto does not support incremental hashing"))
          Resource.make(err)(_ => err.void)
        }

        override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] =
          F.fromPromise(
            F.delay(
              crypto.subtle.digest(algorithm.toStringWebCrypto, data.toUint8Array.buffer)))
            .map(ByteVector.view)
      }
}
