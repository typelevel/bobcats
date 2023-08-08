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
import java.security.MessageDigest
import scodec.bits.ByteVector
import cats.Functor
import cats.effect.Sync
import fs2.{Chunk, Pipe, Stream}

private abstract class JavaSecurityDigest[F[_]](implicit F: Functor[F])
    extends UnsealedHash1[F] {

  def hash: F[MessageDigest]

  override def digest(data: ByteVector): F[ByteVector] =
    hash.map { h =>
      h.update(data.toByteBuffer)
      ByteVector.view(h.digest())
    }

  override val pipe: Pipe[F, Byte, Byte] =
    in =>
      Stream
        .eval(hash)
        .flatMap { h =>
          in.chunks.fold(h) { (h, data) =>
            h.update(data.toByteBuffer)
            h
          }
        }
        .flatMap { h => Stream.chunk(Chunk.array(h.digest())) }

  override def toString = hash.toString
}

private[bobcats] trait Hash1CompanionPlatform {

  /**
   * Wraps a `MessageDigest` which is assumed to be `Cloneable`.
   */
  private[bobcats] def fromMessageDigestCloneableUnsafe[F[_]](messageDigest: MessageDigest)(
      implicit F: Sync[F]): Hash1[F] = new JavaSecurityDigest {
    override val hash: F[MessageDigest] =
      F.delay(messageDigest.clone().asInstanceOf[MessageDigest])
  }

  def fromName[F[_]](name: String)(implicit F: Sync[F]): F[Hash1[F]] = F.delay {
    val hash = MessageDigest.getInstance(name)
    try {
      fromMessageDigestCloneableUnsafe(hash.clone().asInstanceOf[MessageDigest])
    } catch {
      case _: CloneNotSupportedException =>
        new JavaSecurityDigest {
          override val hash: F[MessageDigest] = F.delay(MessageDigest.getInstance(name))
        }
    }
  }

  def apply[F[_]](algorithm: HashAlgorithm)(implicit F: Sync[F]): F[Hash1[F]] = fromName(
    algorithm.toStringJava)

}
