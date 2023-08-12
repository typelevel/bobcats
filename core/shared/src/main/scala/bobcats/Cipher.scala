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

sealed trait Cipher[F[_]] extends CipherPlatform[F] {

  def importKey[A <: Algorithm](
      key: ByteVector,
      algorithm: A): F[SecretKey[A]]

  def encrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
      key: SecretKey[A],
      params: P,
      data: ByteVector): F[ByteVector]

  // def generateIv[A <: CipherAlgorithm](algorithm: A): F[IvParameterSpec[A]]
  // def generateKey[A <: CipherAlgorithm](algorithm: A): F[SecretKey[A]]
  // def importIv[A <: CipherAlgorithm](iv: ByteVector, algorithm: A): F[IvParameterSpec[A]]
  // def importKey[A <: CipherAlgorithm](key: ByteVector, algorithm: A): F[SecretKey[A]]
  // def encrypt[A <: CipherAlgorithm](params: CipherParams[A], data: ByteVector): F[ByteVector]
  // def decrypt[A <: CipherAlgorithm](params: CipherParams[A], data: ByteVector): F[ByteVector]

}

private[bobcats] trait UnsealedCipher[F[_]] extends Cipher[F]

object Cipher extends CipherCompanionPlatform {

  def apply[F[_]](implicit cipher: Cipher[F]): cipher.type = cipher

}
