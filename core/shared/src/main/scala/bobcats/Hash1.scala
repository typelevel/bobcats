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

import fs2.Pipe
import scodec.bits.ByteVector

/**
 * Hash for a single algorithm.
 *
 * Use this class if you have a specific `HashAlgorithm` known in advance or you're using a
 * customized algorithm not covered by the `HashAlgorithm` class.
 */
sealed trait Hash1[F[_]] {
  def digest(data: ByteVector): F[ByteVector]
  def pipe: Pipe[F, Byte, Byte]
}

private[bobcats] trait UnsealedHash1[F[_]] extends Hash1[F]

object Hash1 extends Hash1CompanionPlatform
