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
* The ByteVector is PKCS8 encoded data
* (todo: Q: what is role the algorithm as that could be extracted from the ByteVector?)
* todo: should therefore be called Pkcs8PrivateKeySpec?
* note: JSON Web Key is the future
*/
final case class PrivateKeySpec[+A <: PrivateKeyAlg](key: ByteVector, algorithm: A)
  extends PrivateKey[A] with PrivateKeySpecPlatform[A]

/* The ByteVector is X509 encoded data
* todo: renome to X509PublicKeySpec
* q: what is the role of the algorithm?
* note: JSON Web Key is the future
*/
final case class PublicKeySpec[+A <: PKA](key: ByteVector, algorithm: A)
  extends PublicKey[A] with PublicKeySpecPlatform[A]

