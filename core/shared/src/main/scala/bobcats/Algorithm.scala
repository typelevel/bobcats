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

  case object SHA512 extends HashAlgorithm {
    private[bobcats] override def toStringJava: String = "SHA-512"
    private[bobcats] override def toStringNodeJS: String = "sha512"
    private[bobcats] override def toStringWebCrypto: String = "SHA-512"
  }
}

sealed trait HmacAlgorithm extends Algorithm {

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

sealed trait CipherParams
sealed trait CipherAlgorithm[P <: CipherParams] extends Algorithm

sealed trait BlockCipherAlgorithm[P <: CipherParams] extends CipherAlgorithm[P] {
  private[bobcats] def blockSize: Int
}

sealed trait BlockCipherMode {

  import BlockCipherMode._

  private[bobcats] def toStringUppercase = this match {
    case CBC => "CBC"
    case GCM => "GCM"
    case CTR => "CTR"
  }

}

object BlockCipherMode {

  case object CBC extends BlockCipherMode
  case object GCM extends BlockCipherMode
  case object CTR extends BlockCipherMode

  private[bobcats] def fromStringUppercase(s: String): Option[BlockCipherMode] = s match {
    case "CBC" => Some(CBC)
    case "GCM" => Some(GCM)
    case "CTR" => Some(CTR)
    case _ => None
  }
}

final class IV private[bobcats] (val data: ByteVector) extends AnyVal {
  private[bobcats] def bitLength: Int = data.length.toInt * 8
}

object BlockCipherAlgorithm {

  sealed trait AES[P <: CipherParams] extends CipherAlgorithm[P] {
    def keyLength: AES.KeyLength

    private[bobcats] def toStringJava: String = "AES"

    def toStringNodeJS: String = ???
    def toStringWebCrypto: String = ???

  }

  object AES {

    final class KeyLength private[AES] (val value: Int) extends AnyVal {
      private[bobcats] def toInt: Int = value
    }

    object KeyLength {
      val `128` = new KeyLength(128)
      val `192` = new KeyLength(192)
      val `256` = new KeyLength(256)
    }

    final class TagLength private[bobcats] (val value: Int) extends AnyVal {
      private[bobcats] def byteLength: Int = value / 8
    }

    object TagLength {
      val `96` = new TagLength(96)
      val `104` = new TagLength(104)
      val `112` = new TagLength(112)
      val `120` = new TagLength(120)
      val `128` = new TagLength(128)
    }

    sealed trait CBC extends AES[CBC.Params]

    object CBC {
      final case class Params(iv: IV) extends CipherParams
    }

    sealed trait GCM extends AES[GCM.Params] {
      override def toString: String = s"AESGCM${keyLength.toInt}"
    }

    object GCM {
      final case class Params(
          iv: IV,
          tagLength: TagLength = TagLength.`96`,
          ad: ByteVector = ByteVector.empty)
          extends CipherParams
    }

  }

  object AESCBC128 extends AES.CBC {
    val keyLength = AES.KeyLength.`128`
  }

  object AESCBC256 extends AES.CBC {
    val keyLength = AES.KeyLength.`256`
  }

  object AESGCM128 extends AES.GCM {
    val keyLength = AES.KeyLength.`128`
  }

  object AESGCM192 extends AES.GCM {
    val keyLength = AES.KeyLength.`192`
  }

  object AESGCM256 extends AES.GCM {
    val keyLength = AES.KeyLength.`256`
  }

}

// case class AES[K <: Singleton, M <: BlockCipher.Mode] private(keyLength: K, mode: M, padding: Boolean) extends CipherAlgorithm

// sealed trait CipherParam[A]

// object AES {

//   import BlockCipher.Mode._

//   object CBC {
//     case class Param[A](iv: ByteVector) extends CipherParam[AES[_, CBC.type]]
//   }

//   object CBC128 {
//     def apply(padded: Boolean): AES[128, CBC.type] = new AES[128, CBC.type](128, CBC, padded)
//   }

// }

// // sealed trait CipherParams[A <: CipherAlgorithm]

// // sealed trait AESGCM128

// // // TODO: Should I differentiate between the two?
// // sealed trait CipherAlgorithm extends Algorithm with CipherAlgorithmPlatform {
// //   private[bobcats] def paddingMode: PaddingMode
// //   private[bobcats] def toModeStringJava: String
//   private[bobcats] def recommendedIvLength: Int
//   private[bobcats] def keyLength: Int
// }

// final class IV[+A <: CipherAlgorithm](data: ByteVector)

// object CipherAlgorithm {

//   private[bobcats] def fromStringJava(algorithm: String): Option[CipherAlgorithm] =
//     algorithm match {
//       case "AES/CBC/NoPadding" => Some(AESCBC256(PaddingMode.None))
//       case "AES/CBC/PKCS5Padding" => Some(AESCBC256(PaddingMode.PKCS7))
//       case "AES/GCM/NoPadding" => Some(AESGCM256(PaddingMode.None))
//       case "AES/GCM/PKCS5Padding" => Some(AESGCM256(PaddingMode.PKCS7))
//       case _ => None
//     }

//   sealed trait AESAlgorithm extends CipherAlgorithm {
//     private[bobcats] def toStringJava: String = "AES"
//   }

//   sealed trait AESCBC extends AESAlgorithm {
//     private[bobcats] override def recommendedIvLength: Int = 16
//     private[bobcats] override def toStringWebCrypto: String = "AES-CBC"
//   }

//   object AESCBC {
//     case class Parameters[A <: AESCBC](iv: Iv[A]) extends CipherParameters[A]
//   }

//   case class AESCBC256(paddingMode: PaddingMode) extends AESCBC {
//     private[bobcats] override def toModeStringJava: String =
//       s"AES/CBC/${paddingMode.toStringJava}"
//     private[bobcats] override def toStringNodeJS: String = "aes-256-cbc"
//     private[bobcats] override def keyLength: Int = 256
//   }

//   sealed trait AESGCM extends AESAlgorithm {
//     private[bobcats] override def recommendedIvLength: Int = 12
//     private[bobcats] override def toStringWebCrypto: String = "AES-GCM"
//   }

//   object AESGCM {
//     case class Parameters[A <: AESGCM](iv: Iv[A], tagLength: Option[Int]) extends CipherParameters[A]
//   }

//   case class AESGCM256(paddingMode: PaddingMode) extends AESGCM {
//     private[bobcats] override def toModeStringJava: String =
//       s"AES/GCM/${paddingMode.toStringJava}"
//     private[bobcats] override def toStringNodeJS: String = "aes-256-gcm"
//     private[bobcats] override def keyLength: Int = 256
//   }
// }

// sealed trait AlgorithmParameterSpec[+A <: Algorithm] extends AlgorithmParameterSpecPlatform[A]

// // Iv must be random

// // TODO:
// case class IvParameterSpec[+A <: CipherAlgorithm](
//     initializationVector: ByteVector,
//     algorithm: A)
//     extends AlgorithmParameterSpec[A]
//     with IvParameterSpecPlatform[A]
