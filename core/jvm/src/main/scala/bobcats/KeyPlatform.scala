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

import java.math.BigInteger
import java.security
import java.security.KeyFactory
import java.security.spec.{EdECPublicKeySpec, NamedParameterSpec}
import javax.crypto

private[bobcats] trait KeyPlatform {}

private[bobcats] trait PublicKeyPlatform {
  def toJava: security.PublicKey
}

private[bobcats] trait PrivateKeyPlatform {
  def toJava: security.PrivateKey
}

private[bobcats] trait SecretKeyPlatform {
  def toJava: crypto.SecretKey
}

private[bobcats] trait SecretKeySpecPlatform[+A <: Algorithm] { self: SecretKeySpec[A] =>
  def toJava: crypto.spec.SecretKeySpec =
    new crypto.spec.SecretKeySpec(key.toArray, algorithm.toStringJava)

}
//todo: should this class should be renamed to PKCS8PrivateKeySpec?
private[bobcats] trait PKCS8KeySpecPlatform[+A <: AsymmetricKeyAlg] extends PrivateKeyPlatform {
  self: PKCS8KeySpec[A] =>
  def toJava: security.PrivateKey = {
    val kf: KeyFactory = KeyFactory.getInstance(algorithm.toStringJava)
    kf.generatePrivate(toJavaSpec)
  }

  def toJavaSpec: java.security.spec.PKCS8EncodedKeySpec =
    new java.security.spec.PKCS8EncodedKeySpec(key.toArray, algorithm.toStringJava)
}

private[bobcats] trait SPKIKeySpecPlatform[+A <: AsymmetricKeyAlg] extends PublicKeyPlatform {
  self: SPKIKeySpec[A] =>
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

private[bobcats] trait JWKPublicKeySpecPlatform[+A <: AsymmetricKeyAlg]
    extends PublicKeyPlatform { self: JWKPublicKeySpec[A] =>
  // todo: should del with parse exceptions
  def toJava: security.PublicKey = {
    import com.nimbusds.jose.jwk.JWK

    import scala.jdk.CollectionConverters.MapHasAsJava
    val jwk: JWK = JWK.parse(key.asInstanceOf[Map[String, Object]].asJava)
    val pubJWK = jwk.toPublicJWK
    pubJWK.getKeyType.getValue match {
      case "EC" => pubJWK.toECKey.toPublicKey
      case "RSA" => pubJWK.toRSAKey.toPublicKey
      case "OKP" => { // Ed25519
        // jwk.toOctetKeyPair.toPublicKey
        // that will throw an exception as nimbus have not yet provided an implementation
        // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/359/add-export-to-java-keypair-from
        // but we can use https://curity.io/resources/learn/jwt-signatures/ on jdk15+
        val okp = pubJWK.toOctetKeyPair
        val publicKeyBytes: Array[Byte] = okp.getX.decode()
        // Byte array is in little endian encoding// Byte array is in little endian encoding

        // https://www.rfc-editor.org/rfc/rfc8032.html#section-3.1
        // The most significant bit in final octet indicates if X is negative or not:
        val b: Int = publicKeyBytes.length
        val xBit: Boolean = (publicKeyBytes(b - 1) & 0x80) != 0

        // Recover y value by clearing x-bit.
        publicKeyBytes(b - 1) = (publicKeyBytes(b - 1) & 0x7f).asInstanceOf[Byte]

        // Switch to big endian encoding
        val publicKeyBytesBE = new Array[Byte](b)
        var i = 0
        while ({ i < b }) {
          publicKeyBytesBE(i) = publicKeyBytes(b - 1 - i)

          i += 1
        }

        val y = new BigInteger(1, publicKeyBytesBE)
        // Load parameters from Ed25519
        val pubSpec = new EdECPublicKeySpec(
          NamedParameterSpec.ED25519,
          new java.security.spec.EdECPoint(xBit, y))

        // Generate an EdDSA Public Key from the point on Ed25519
        val kf = KeyFactory.getInstance("EdDSA")
        kf.generatePublic(pubSpec)
      }
    }

  }
}

private[bobcats] trait JWKPrivateKeySpecPlatform[+A <: AsymmetricKeyAlg]
    extends PrivateKeyPlatform {
  self: JWKPrivateKeySpec[A] =>
  def toJava: security.PrivateKey = {
    import com.nimbusds.jose.jwk.JWK

    import scala.jdk.CollectionConverters.MapHasAsJava
    val jwk: JWK = JWK.parse(key.asInstanceOf[Map[String, Object]].asJava)
    jwk.getKeyType.getValue match {
      case "EC" => jwk.toECKey.toPrivateKey
      case "RSA" => jwk.toRSAKey.toPrivateKey
      case "OKP" => { // Ed25519
        // jwk.toOctetKeyPair.toPrivateKey
        // that will throw an exception as nimbus have not yet provided an implementation
        // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/359/add-export-to-java-keypair-from
        // but we can use https://curity.io/resources/learn/jwt-signatures/ on jdk15+
        // todo: map the other NamedParameterSpec types
        val privSpec = new java.security.spec.EdECPrivateKeySpec(
          java.security.spec.NamedParameterSpec.ED25519,
          jwk.toOctetKeyPair.getDecodedD)
        val kf = KeyFactory.getInstance("EdDSA")
        kf.generatePrivate(privSpec)
      }
    }
  }
}
