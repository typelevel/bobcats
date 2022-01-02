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
    private[bobcats] override def toStringJava: String = "SHA-1"
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
sealed trait AsymmetricKeyAlg extends Algorithm

object AsymmetricKeyAlg {

  sealed trait Signature extends Algorithm with SignaturePlatform {
    def hash: HashAlgorithm
  }

  // key types
  trait RSA
  trait EC

  sealed trait EC_Curve
  case object `P-256` extends EC_Curve
  case object `P-384` extends EC_Curve
  case object `P-521` extends EC_Curve

  case class ECKey(val curve: EC_Curve) extends AsymmetricKeyAlg with EC {
    override private[bobcats] def toStringJava = "EC"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "ECDSA"
  }

  case object RSA_PKCS_Key extends AsymmetricKeyAlg with RSA {
    override private[bobcats] def toStringJava = "RSA"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "RSASSA-PKCS1-v1_5"
  }

  case object RSA_PSS_Key extends AsymmetricKeyAlg with RSA {
    override private[bobcats] def toStringJava = "RSASSA-PSS"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "RSA-PSS"
  }

  case object SHA512 extends RSA_PKCS_Sig {
    override private[bobcats] def toStringJava = "SHA512withRSA"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = ???

    override def hash: HashAlgorithm =
      HashAlgorithm.SHA512 // is this right? OR should it be optional?
  }

  // NOTE: Java Crypto and JS Web Crypto API split attributes in different ways.
  // JavaCrypto:
  //   a. builds a key with minimal key information
  //   b. passes the hash as part of the singing process
  // JS WCA (for PSS and RSA)
  //   a. requires the hash to be part of the key generation process
  //   b. does not require the hash to be specified in the signing process
  // BUT JS WCA for ECDSA
  //   a. passes the name of the curve instead of the hash (e.g. P-384)
  //   b. requires the hash to be part of the signing and verification

  trait RSA_PSS_Sig extends Signature with RSA {
    override private[bobcats] def toStringJava = "RSASSA-PSS"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto = "RSA-PSS"
    def saltLength: Int
  }

  trait RSA_PKCS_Sig extends Signature with RSA {
    override private[bobcats] def toStringWebCrypto = "RSASSA-PKCS1-v1_5"
  }

  abstract class EC_Sig extends Signature with EC {
    def ecKeyAlg: ECKey // todo: don't think it is needed
  }

  // this makes one think if perhaps all the methods should not go the the SignaturePlatform?
  // this is defined here:
  // https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html#section-3.3.1
  // note PSS requires extra arguments to be passed.
  case object `rsa-pss-sha512` extends RSA_PSS_Sig {
    override def saltLength: Int = 64
    override def hash: HashAlgorithm =
      HashAlgorithm.SHA512 // is this right? OR should it be optional?
  }

  case object `rsa-v1_5-sha256` extends RSA_PKCS_Sig {
    override private[bobcats] def toStringJava = "SHA256withRSA"
    override private[bobcats] def toStringNodeJS = ???
    override def hash: HashAlgorithm =
      HashAlgorithm.SHA256 // is this right? OR should it be optional?
  }

  case object `ecdsa-p256-sha256` extends EC_Sig {
    override def ecKeyAlg: ECKey = ECKey(AsymmetricKeyAlg.`P-256`)
    // for the names see https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms
    override private[bobcats] def toStringJava = "SHA256withECDSAinP1363Format"
    override private[bobcats] def toStringNodeJS = ???
    override private[bobcats] def toStringWebCrypto =
      "ECDSA" // one has to pass an object with the sha
    override def hash: HashAlgorithm =
      HashAlgorithm.SHA256 // is this right? OR should it be optional?
  }
}
