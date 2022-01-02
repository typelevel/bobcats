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

import javax.crypto
import java.security
import java.security.KeyFactory

private[bobcats] trait KeyPlatform {
  def toJava: security.Key
}

private[bobcats] trait PublicKeyPlatform {
  def toJavaSpec: java.security.spec.X509EncodedKeySpec
}

private[bobcats] trait PrivateKeyPlatform {
  def toJava: security.PrivateKey
  def toJavaSpec: java.security.spec.PKCS8EncodedKeySpec
}

private[bobcats] trait SecretKeyPlatform {
  def toJava: crypto.SecretKey
}

private[bobcats] trait SecretKeySpecPlatform[+A <: Algorithm] { self: SecretKeySpec[A] =>
  def toJava: crypto.spec.SecretKeySpec =
    new crypto.spec.SecretKeySpec(key.toArray, algorithm.toStringJava)

}

private[bobcats] trait PKCS8KeySpecPlatform[+A <: AsymmetricKeyAlg] {
  self: PKCS8KeySpec[A] =>
  def toJava: security.PrivateKey = {
    val kf: KeyFactory = KeyFactory.getInstance(algorithm.toStringJava)
    kf.generatePrivate(toJavaSpec)
  }

  // this class should be renamed PKCS8PrivateKeySpec
  def toJavaSpec: java.security.spec.PKCS8EncodedKeySpec =
    new java.security.spec.PKCS8EncodedKeySpec(key.toArray, algorithm.toStringJava)
}

private[bobcats] trait SPKIKeySpecPlatform[+A <: AsymmetricKeyAlg] { self: SPKIKeySpec[A] =>
  def toJava: security.PublicKey = {
    val kf: KeyFactory = KeyFactory.getInstance(algorithm.toStringJava)
    kf.generatePublic(toJavaSpec)
  }
  // we see here that something is not quite right. If there is an encoding of a key - an tuple
  // of numbers essentially, then there can be many encodings. Which one should one use?
  // I would not be surprised if there are more than one ways to encode this number.
  // If so we should have a constructor such as `(Array, type) => Option[PubKey]`
  // but perhaps that is what this is...
  def toJavaSpec: java.security.spec.X509EncodedKeySpec =
    new java.security.spec.X509EncodedKeySpec(key.toArray)
}
