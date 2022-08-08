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

sealed trait Algorithm extends AlgorithmPlatform {
  private[bobcats] def toStringJava: String
  private[bobcats] def toStringNodeJS: String
  private[bobcats] def toStringWebCrypto: String
}

sealed trait HashAlgorithm extends Algorithm with HashAlgorithmPlatform
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

  case object SHA512 extends HashAlgorithm {
    private[bobcats] override def toStringJava: String = "SHA-512"
    private[bobcats] override def toStringNodeJS: String = "sha512"
    private[bobcats] override def toStringWebCrypto: String = "SHA-512"
  }
}

sealed trait HmacAlgorithm extends Algorithm with HmacAlgorithmPlatform {

  import HmacAlgorithm._
  
  private[bobcats] def minimumKeyLength: Int
  private[bobcats] def hashAlgorithm: HashAlgorithm = this match {
    case SHA1 => HashAlgorithm.SHA1
    case SHA256 => HashAlgorithm.SHA256
    case SHA512 => HashAlgorithm.SHA512
  }
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

sealed trait CipherAlgorithm extends Algorithm with CipherAlgorithmPlatform {
  private[bobcats] def paddingMode: PaddingMode
  private[bobcats] def toModeStringJava: String
  private[bobcats] def recommendedIvLength: Int
  private[bobcats] def keyLength: Int
}

object CipherAlgorithm {
  private[bobcats] def fromStringJava(algorithm: String): Option[CipherAlgorithm] =
    algorithm match {
      case "AES/CBC/NoPadding" => Some(AESCBC256(PaddingMode.None))
      case "AES/CBC/PKCS5Padding" => Some(AESCBC256(PaddingMode.PKCS7))
      case "AES/GCM/NoPadding" => Some(AESGCM256(PaddingMode.None))
      case "AES/GCM/PKCS5Padding" => Some(AESGCM256(PaddingMode.PKCS7))
      case _ => None
    }

  sealed trait AESAlgorithm extends CipherAlgorithm {
    private[bobcats] def toStringJava: String = "AES"
  }

  sealed trait AESCBCAlgorithm extends AESAlgorithm {
    private[bobcats] override def recommendedIvLength: Int = 16
    private[bobcats] override def toStringWebCrypto: String = "AES-CBC"
  }

  case class AESCBC256(paddingMode: PaddingMode) extends AESCBCAlgorithm {
    private[bobcats] override def toModeStringJava: String =
      s"AES/CBC/${paddingMode.toStringJava}"
    private[bobcats] override def toStringNodeJS: String = "aes-256-cbc"
    private[bobcats] override def keyLength: Int = 256
  }

  sealed trait AESGCMAlgorithm extends AESAlgorithm {
    private[bobcats] override def recommendedIvLength: Int = 12
    private[bobcats] override def toStringWebCrypto: String = "AES-GCM"
  }

  case class AESGCM256(paddingMode: PaddingMode) extends AESGCMAlgorithm {
    private[bobcats] override def toModeStringJava: String =
      s"AES/GCM/${paddingMode.toStringJava}"
    private[bobcats] override def toStringNodeJS: String = "aes-256-gcm"
    private[bobcats] override def keyLength: Int = 256
  }
}

sealed trait AlgorithmParameterSpec[+A <: Algorithm] extends AlgorithmParameterSpecPlatform[A]

case class IvParameterSpec[+A <: CipherAlgorithm](
    initializationVector: ByteVector,
    algorithm: A)
    extends AlgorithmParameterSpec[A]
    with IvParameterSpecPlatform[A]
