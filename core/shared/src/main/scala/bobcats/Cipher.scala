package bobcats

import scodec.bits.ByteVector

sealed trait Cipher[F[_]] extends CipherPlatform[F] {
  def generateIv[A <: CipherAlgorithm](algorithm: A): F[IvParameterSpec[A]]
  def generateKey[A <: CipherAlgorithm](algorithm: A): F[SecretKey[A]]
  def importIv[A <: CipherAlgorithm](iv: ByteVector, algorithm: A): F[IvParameterSpec[A]]
  def importKey[A <: CipherAlgorithm](key: ByteVector, algorithm: A): F[SecretKey[A]]
  def encrypt[A <: CipherAlgorithm](key: SecretKey[A], iv: IvParameterSpec[A], data: ByteVector): F[ByteVector]
  def decrypt[A <: CipherAlgorithm](key: SecretKey[A], iv: IvParameterSpec[A], data: ByteVector): F[ByteVector]
}

private[bobcats] trait UnsealedCipher[F[_]] extends Cipher[F]

object Cipher extends CipherCompanionPlatform {

  def apply[F[_]](implicit cipher: Cipher[F]): cipher.type = cipher

}
