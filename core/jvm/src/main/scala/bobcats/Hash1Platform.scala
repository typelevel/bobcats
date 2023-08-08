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

import java.security.MessageDigest
import scodec.bits.ByteVector
import cats.Applicative
import cats.effect.Sync
import fs2.{Chunk, Stream}

private final class JavaSecurityDigest[F[_]](val hash: MessageDigest)(
    implicit F: Applicative[F])
    extends UnsealedHash1[F] {

  override def digest(data: ByteVector): F[ByteVector] = F.pure {
    val h = hash.clone().asInstanceOf[MessageDigest]
    h.update(data.toByteBuffer)
    ByteVector.view(h.digest())
  }
  override def digest(data: Stream[F, Byte]): Stream[F, Byte] =
    data
      .chunks
      .fold(hash.clone().asInstanceOf[MessageDigest]) { (h, data) =>
        h.update(data.toByteBuffer)
        h
      }
      .flatMap { h => Stream.chunk(Chunk.array(h.digest())) }

  override def toString = hash.toString
}

private[bobcats] trait Hash1CompanionPlatform {

  private[bobcats] def fromMessageDigestUnsafe[F[_]: Applicative](
      digest: MessageDigest): Hash1[F] = new JavaSecurityDigest(digest)

  def fromName[F[_]](name: String)(implicit F: Sync[F]): F[Hash1[F]] = F.delay {
    val hash = MessageDigest.getInstance(name)
    fromMessageDigestUnsafe(hash)
  }

  def apply[F[_]](algorithm: HashAlgorithm)(implicit F: Sync[F]): F[Hash1[F]] = fromName(
    algorithm.toStringJava)

}
