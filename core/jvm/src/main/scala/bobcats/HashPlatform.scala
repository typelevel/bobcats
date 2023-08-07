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
import scodec.bits.ByteVector

import java.security.MessageDigest

private final class JavaSecurityDigest[F[_]](val hash: MessageDigest)(implicit F: Sync[F])
    extends UnsealedDigest[F] {

  override def update(data: ByteVector): F[Unit] = F.delay(hash.update(data.toByteBuffer))
  override val reset = F.delay(hash.reset())
  override def get: F[ByteVector] = F.delay(ByteVector.view(hash.digest()))
}

private[bobcats] trait HashCompanionPlatform {

  private[bobcats] def forSync[F[_]](implicit F: Sync[F]): Hash[F] =
    new UnsealedHash[F] {
      override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] =
        F.catchNonFatal {
          val hash = MessageDigest.getInstance(algorithm.toStringJava)
          hash.update(data.toByteBuffer)
          ByteVector.view(hash.digest())
        }
      override def incremental(algorithm: HashAlgorithm): Resource[F, Digest[F]] = {
        Resource.make(F.delay {
          val hash = MessageDigest.getInstance(algorithm.toStringJava)
          new JavaSecurityDigest[F](hash)(F)
        })(_.reset)
      }
    }

  implicit def forAsync[F[_]](implicit F: Async[F]): Hash[F] = forSync(F)
}
