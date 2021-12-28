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

sealed trait Algorithm {
  private[bobcats] def toStringJava: String
  private[bobcats] def toStringNodeJS: String
  private[bobcats] def toStringWebCrypto: String
}

sealed trait HashAlgorithm extends Algorithm
object HashAlgorithm {

  case object MD5 extends HashAlgorithm {
    private[bobcats] override def toStringJava: String = "MD5"
    private[bobcats] override def toStringNodeJS: String = "md5"
    private[bobcats] override def toStringWebCrypto: String =
      throw new UnsupportedOperationException
  }

  case object SHA1 extends HashAlgorithm {
    private[bobcats] override def toStringJava: String = "SHA-356"
    private[bobcats] override def toStringNodeJS: String = "sha1"
    private[bobcats] override def toStringWebCrypto: String = "SHA-1"
  }

  case object SHA256 extends HashAlgorithm {
    private[bobcats] override def toStringJava: String = "SHA-256"
    private[bobcats] override def toStringNodeJS: String = "sha256"
    private[bobcats] override def toStringWebCrypto: String = "SHA-256"
  }

  case object SHA384 extends HashAlgorithm {
    private[bobcats] override def toStringJava: String = "SHA-384"
    private[bobcats] override def toStringNodeJS: String = "sha384"
    private[bobcats] override def toStringWebCrypto: String = "SHA-384"
  }

  case object SHA512 extends HashAlgorithm {
    private[bobcats] override def toStringJava: String = "SHA-512"
    private[bobcats] override def toStringNodeJS: String = "sha512"
    private[bobcats] override def toStringWebCrypto: String = "SHA-512"
  }
}

sealed trait HmacAlgorithm extends Algorithm {
  private[bobcats] def minimumKeyLength: Int
}
object HmacAlgorithm {

  private[bobcats] def fromStringJava(algorithm: String): Option[HmacAlgorithm] =
    algorithm match {
      case "HmacSHA1" => Some(SHA1)
      case "HmacSHA256" => Some(SHA256)
      case "HmacSHA512" => Some(SHA512)
      case _ => None
    }

  case object SHA1 extends HmacAlgorithm {
    private[bobcats] override def toStringJava: String = "HmacSHA1"
    private[bobcats] override def toStringNodeJS: String = "sha1"
    private[bobcats] override def toStringWebCrypto: String = "SHA-1"
    private[bobcats] override def minimumKeyLength: Int = 20
  }

  case object SHA256 extends HmacAlgorithm {
    private[bobcats] override def toStringJava: String = "HmacSHA256"
    private[bobcats] override def toStringNodeJS: String = "sha256"
    private[bobcats] override def toStringWebCrypto: String = "SHA-256"
    private[bobcats] override def minimumKeyLength: Int = 32
  }

  case object SHA512 extends HmacAlgorithm {
    private[bobcats] override def toStringJava: String = "HmacSHA512"
    private[bobcats] override def toStringNodeJS: String = "sha512"
    private[bobcats] override def toStringWebCrypto: String = "SHA-512"
    private[bobcats] override def minimumKeyLength: Int = 64
  }
}

// Public Key Algorithm
sealed trait PKA extends Algorithm {
  type Private <: PrivateKeyAlg //matching private key type
  val Private: Private
}

object PKA {
  def fromStringJava(name: String): Option[PKA] =
    name match {
      case "RSA" => Some(RSA)
      case "ECDSA" => Some(EC)
      case _ =>
          println(s"PKA.fromStringJava($name)")
          None
    }


  sealed trait Signature extends Algorithm with SignaturePlatform {
    def hash: HashAlgorithm
  }

  trait RSA_Signature extends Signature with RSA

  trait RSA
  trait EC
  //not sure what a good name for this is, or if that is the right object
  case object RSA extends PKA with RSA {
    override type Private = PrivateKeyAlg.RSA.type
    override val Private = PrivateKeyAlg.RSA

    override private[bobcats] def toStringJava = "RSA"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = ???
  }

  case object EC extends PKA with EC {
    override type Private = PrivateKeyAlg.EC.type
    override val Private = PrivateKeyAlg.EC

    override private[bobcats] def toStringJava = "EC"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = ???
  }

  case object SHA512 extends RSA_Signature {
    override private[bobcats] def toStringJava = "SHA512withRSA"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = ???

    override def hash: HashAlgorithm = HashAlgorithm.SHA512 // is this right? OR should it be optional?
  }

  //NOTE: Java Crypto and JS Web Crypto API split attributes in different ways.
  // JavaCrypto:
  //   a. builds a key with minimal key information
  //   b. passes the hash as part of the singing process
  // JS WCA (for PSS and RSA)
  //   a. requires the hash to be part of the key generation process
  //   b. does not require the hash to be specified in the signing process
  // BUT JS WCA for ECDSA
  //   a. passes the name of the curve instead of the hash (e.g. P-384)
  //   b. requires the hash to be part of the signing and verification

  abstract class RSA_PSS extends Signature with RSA {
    def saltLength: Int
  }

  abstract class EC_Sig extends Signature with EC

  // this makes one think if perhaps all the methods should not go the the SignaturePlatform?
  // this is defined here:
  // https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html#section-3.3.1
  case object `rsa-pss-sha512` extends RSA_PSS {
    override private[bobcats] def toStringJava = ???
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "RSA-PSS"

    override def saltLength: Int = 64
    override def hash: HashAlgorithm = HashAlgorithm.SHA512 // is this right? OR should it be optional?
  }

  case object `rsa-v1_5-sha256` extends RSA_Signature {
    override private[bobcats] def toStringJava = "SHA256withRSA"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = ???
    override def hash: HashAlgorithm = HashAlgorithm.SHA256 // is this right? OR should it be optional?
  }

  case object `ecdsa-p256-sha256` extends EC_Sig {
    override private[bobcats] def toStringJava = "SHA256withECDSA"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "ECDSA" // one has to pass an object with the sha
    override def hash: HashAlgorithm = HashAlgorithm.SHA256 // is this right? OR should it be optional?
  }
}

sealed trait PrivateKeyAlg extends Algorithm

object PrivateKeyAlg {
  def fromStringJava(name: String): Option[PrivateKeyAlg] =
    name match {
      case "RSA" => Some(RSA)
      case "ECDSA" => Some(EC)
      case "RSASSA-PSS" => Some(`RSASSA-PSS`)
      case _ =>
        println(s"PrivateKeyAlg.fromStringJava($name)")
        None
    }

  //not sure what a good name for this is, or if that is the right object, should it perhaps just be RSA?
  //like the matching private key?
  //it may be good for Public/Private keys to have them defined clearly as pairs, so as to
  //help developers find the matching piece via the type system.
  case object RSA extends PrivateKeyAlg {
    override private[bobcats] def toStringJava = "RSA"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "RSASSA-PKCS1-v1_5"
  }

  //todo: Is this really different from RSA PrivateKey?
  case object `RSASSA-PSS` extends PrivateKeyAlg {
    override private[bobcats] def toStringJava = "RSASSA-PSS"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "RSA-PSS"
  }

  case object EC extends PrivateKeyAlg {
    override private[bobcats] def toStringJava = "EC"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "ECDSA"
  }
}

