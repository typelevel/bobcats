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

private[bobcats] final class SubtleCryptoDigest[F[_]](algorithm: String)(implicit F: Async[F])
    extends UnsealedHash1[F] {

  import facade.browser._

  override def digest(data: ByteVector): F[ByteVector] =
    F.fromPromise(F.delay(crypto.subtle.digest(algorithm, data.toUint8Array.buffer)))
      .map(ByteVector.view)

  override def pipe: Pipe[F, Byte, Byte] = throw new UnsupportedOperationException(
    "Browsers do not support streaming")

}

private final class NodeCryptoDigest[F[_]](algorithm: String)(implicit F: Sync[F])
    extends UnsealedHash1[F] {

  override def digest(data: ByteVector): F[ByteVector] =
    F.pure {
      // Assume we've checked the algorithm already
      val hash = facade.node.crypto.createHash(algorithm)
      hash.update(data.toUint8Array)
      ByteVector.view(hash.digest())
    }

  override val pipe: Pipe[F, Byte, Byte] =
    in =>
      Stream.eval(F.delay(facade.node.crypto.createHash(algorithm))).flatMap { hash =>
        in.chunks
          .fold(hash) { (h, d) =>
            h.update(d.toUint8Array)
            h
          }
          .flatMap(h => Stream.chunk(Chunk.uint8Array(h.digest())))
      }
}

private[bobcats] trait Hash1CompanionPlatform {
  private[bobcats] def fromJSCryptoName[F[_]](alg: String)(implicit F: Sync[F]): F[Hash1[F]] =
    if (facade.node.crypto.getHashes().contains(alg)) {
      F.pure(new NodeCryptoDigest(alg)(F))
    } else {
      F.raiseError(new NoSuchAlgorithmException(s"${alg} MessageDigest not available"))
    }

  def forAsync[F[_]: Async](algorithm: HashAlgorithm): Resource[F, Hash1[F]] =
    if (facade.isNodeJSRuntime) Resource.eval(fromJSCryptoName(algorithm.toStringNodeJS))
    else {
      // SubtleCrypto does not have a way of checking the supported hashes
      Resource.pure(new SubtleCryptoDigest(algorithm.toStringWebCrypto))
    }
}
