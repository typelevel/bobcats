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

import java.security.{MessageDigest, Provider}
import scodec.bits.ByteVector
import cats.Applicative
import cats.effect.Sync
import fs2.{Chunk, Pipe, Stream}

private final class JavaSecurityDigest[F[_]](algorithm: String, provider: Provider)(
    implicit F: Applicative[F])
    extends UnsealedHash1[F] {

  override def digest(data: ByteVector): F[ByteVector] = F.pure {
    val h = MessageDigest.getInstance(algorithm, provider)
    h.update(data.toByteBuffer)
    ByteVector.view(h.digest())
  }

  override val pipe: Pipe[F, Byte, Byte] =
    in =>
      in.chunks
        .fold(MessageDigest.getInstance(algorithm, provider)) { (h, data) =>
          h.update(data.toByteBuffer)
          h
        }
        .flatMap { h => Stream.chunk(Chunk.array(h.digest())) }

  override def toString = s"JavaSecurityDigest(${algorithm}, ${provider.getName})"
}

private[bobcats] trait Hash1CompanionPlatform {

  /**
   * Get a hash for a specific name.
   */
  def fromName[F[_], G[_]](name: String)(implicit F: Sync[F], G: Applicative[G]): F[Hash1[G]] =
    F.delay {
      // `Security#getProviders` is a mutable array, so cache the `Provider`
      val p = Providers.get().messageDigest(name) match {
        case Left(e) => throw e
        case Right(p) => p
      }
      new JavaSecurityDigest(name, p)(G)
    }

  def apply[F[_]](algorithm: HashAlgorithm)(implicit F: Sync[F]): F[Hash1[F]] = fromName(
    algorithm.toStringJava)

}
