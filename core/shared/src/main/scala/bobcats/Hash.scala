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

import scodec.bits.ByteVector
import cats.effect.kernel.Resource

/**
 * Used for incremental hashing.
 */
sealed trait Digest[F[_]] {

  /**
   * Updates the digest context with the provided data.
   */
  def update(data: ByteVector): F[Unit]

  /**
   * Returns the final digest.
   */
  def get: F[ByteVector]

  /**
   * Resets the digest to be used again.
   */
  def reset: F[Unit]
}

private[bobcats] trait UnsealedDigest[F[_]] extends Digest[F]

sealed trait Hash[F[_]] {
  def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector]

  /**
   * Create a digest with can be updated incrementally.
   */
  def incremental(algorithm: HashAlgorithm): Resource[F, Digest[F]]
}

private[bobcats] trait UnsealedHash[F[_]] extends Hash[F]

object Hash extends HashCompanionPlatform {

  def apply[F[_]](implicit hash: Hash[F]): hash.type = hash

}
