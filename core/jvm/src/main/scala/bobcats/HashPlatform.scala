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

import cats.ApplicativeThrow
import scodec.bits.ByteVector
import java.security.MessageDigest

private[bobcats] trait HashCompanionPlatform {
  val SHA1 = "SHA-1"
  val SHA256 = "SHA-256"

  implicit def forApplicativeThrow[F[_]](implicit F: ApplicativeThrow[F]): Hash[F] =
    new Hash[F] {
      override def digest(algorithm: String, data: ByteVector): F[ByteVector] =
        F.catchNonFatal {
          val hash = MessageDigest.getInstance(algorithm)
          hash.update(data.toByteBuffer)
          ByteVector.view(hash.digest())
        }
    }
}
