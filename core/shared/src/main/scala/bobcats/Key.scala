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

sealed trait Key[+A <: Algorithm] extends KeyPlatform {
  def algorithm: A
}

sealed trait PublicKey[+A <: Algorithm] extends Key[A] with PublicKeyPlatform
sealed trait PrivateKey[+A <: Algorithm] extends Key[A] with PrivateKeyPlatform
sealed trait SecretKey[+A <: Algorithm] extends Key[A] with SecretKeyPlatform

final case class SecretKeySpec[+A <: Algorithm](key: ByteVector, algorithm: A)
    extends SecretKey[A]
    with SecretKeySpecPlatform[A]

// In JS the key object is very important as that is what allows one to save
// an opaque (private) key in local storage which is not readable by the code
// calling it.
// todo: how would we represent such an opaque key?

/*
 * Private Key specification given by byte vector in PKCS8 encoded data
 * as defined in RFC5208. These are usually serialised as PEM Documents,
 * starting with "----- BEGIN PRIVATE KEY -----".
 * (Note PEM Documents whose header describes the type of key as "RSA" or "EC"
 * as in "----- BEGIN PRIVATE EC KEY-----" are PKCS1 documents that won't work
 * here. They can be upgraded using
 * > openssl pkcs8 -topk8 -inform PEM -in spec.private.pem -out private.pem -nocrypt
 * Or other tools/libraries such as Bouncy Castle.
 *
 * The key is the byte content of PEM encoded PKCS8 data
 * todo: Question: Is having the algorithm as a generic useful?
 *   Subclassing might be more appropriate.
 */
final case class PKCS8KeySpec[+A <: AsymmetricKeyAlg](key: ByteVector, algorithm: A)
    extends PrivateKey[A]
    with PKCS8KeySpecPlatform[A]

/*
 * Public Key specification given by byte vector as Simple public key infrastructure (SPKI)
 * encoded data. These are often serialised as PEM Documents starting with
 * "----- BEGIN PUBLIC KEY -----"
 *
 * * The key is the byte content of PEM encoded SPKI data. See test suite.
 * todo: Question: Is having the algorithm as a generic useful?
 *   Subclassing might be more appropriate.
 */
final case class SPKIKeySpec[+A <: AsymmetricKeyAlg](key: ByteVector, algorithm: A)
    extends PublicKey[A]
    with SPKIKeySpecPlatform[A]
