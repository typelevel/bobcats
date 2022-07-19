package bobcats

import cats.effect.kernel.Async
import cats.syntax.all._
import scodec.bits.ByteVector

import scala.scalajs.js
import java.lang

private[bobcats] trait CipherPlatform[F[_]]

private[bobcats] trait CipherCompanionPlatform {
  implicit def forAsync[F[_]](implicit F: Async[F]): Cipher[F] = {
    if (facade.isNodeJSRuntime)
      new UnsealedCipher[F] {
        import facade.node._

        override def generateIv[A <: CipherAlgorithm](algorithm: A): F[IvParameterSpec[A]] =
          F.async_[IvParameterSpec[A]] { cb =>
            crypto.randomBytes(
              algorithm.recommendedIvLength,
              (err, iv) =>
                cb(
                  Option(err)
                    .map(js.JavaScriptException)
                    .toLeft(IvParameterSpec(ByteVector.view(iv), algorithm))
                )
            )
          }

        override def generateKey[A <: CipherAlgorithm](algorithm: A): F[SecretKey[A]] =
          F.async_[SecretKey[A]] { cb =>
            crypto.generateKey(
              "aes",
              GenerateKeyOptions(algorithm.keyLength * lang.Byte.SIZE),
              (err, key) =>
                cb(
                  Option(err)
                    .map(js.JavaScriptException)
                    .toLeft(SecretKeySpec(ByteVector.view(key.`export`()), algorithm)))
            )
          }

        override def importKey[A <: CipherAlgorithm](
            key: ByteVector,
            algorithm: A): F[SecretKey[A]] =
          F.pure(SecretKeySpec(key, algorithm))

        override def importIv[A <: CipherAlgorithm](
            key: ByteVector,
            algorithm: A): F[IvParameterSpec[A]] =
          F.pure(IvParameterSpec(key, algorithm))

        override def encrypt[A <: CipherAlgorithm](
            key: SecretKey[A],
            iv: IvParameterSpec[A],
            data: ByteVector): F[ByteVector] =
          key match {
            case SecretKeySpec(key, algorithm) =>
              F.catchNonFatal {
                val cipher = crypto.createCipheriv(
                  algorithm.toStringNodeJS,
                  key.toUint8Array,
                  iv.initializationVector.toUint8Array
                ).setAutoPadding(algorithm.paddingMode.setAutoPaddingNodeJS)
                val cipherText = cipher.update(data.toUint8Array)
                ByteVector.view(cipherText) ++ ByteVector.view(cipher.`final`())
              }
            case _ => F.raiseError(new InvalidKeyException)
          }

        override def decrypt[A <: CipherAlgorithm](
            key: SecretKey[A],
            iv: IvParameterSpec[A],
            data: ByteVector): F[ByteVector] =
          key match {
            case SecretKeySpec(key, algorithm) =>
              F.catchNonFatal {
                val cipher = crypto.createDecipheriv(
                  algorithm.toStringNodeJS,
                  key.toUint8Array,
                  iv.initializationVector.toUint8Array
                ).setAutoPadding(algorithm.paddingMode.setAutoPaddingNodeJS)
                val cipherText = cipher.update(data.toUint8Array)
                ByteVector.view(cipherText) ++ ByteVector.view(cipher.`final`())
              }
            case _ => F.raiseError(new InvalidKeyException)
          }
      }
    else
      new UnsealedCipher[F] {
        import facade.browser._

        override def generateIv[A <: CipherAlgorithm](algorithm: A): F[IvParameterSpec[A]] =
          F.pure {
            val iv = crypto.getRandomValues(
              new js.typedarray.Uint8Array(algorithm.recommendedIvLength))
            new IvParameterSpec[A](ByteVector.view(iv), algorithm)
          }

        override def generateKey[A <: CipherAlgorithm](algorithm: A): F[SecretKey[A]] =
          for {
            key <- F.fromPromise(
              F.delay(crypto
                .subtle
                .generateKey(AesKeyGenParams(algorithm), true, js.Array("encrypt", "decrypt"))))
            exported <- F.fromPromise(F.delay(crypto.subtle.exportKey("raw", key)))
          } yield SecretKeySpec(ByteVector.view(exported), algorithm)

        override def importKey[A <: CipherAlgorithm](
            key: ByteVector,
            algorithm: A): F[SecretKey[A]] =
          F.pure(SecretKeySpec(key, algorithm))

        override def importIv[A <: CipherAlgorithm](
            key: ByteVector,
            algorithm: A): F[IvParameterSpec[A]] =
          F.pure(IvParameterSpec(key, algorithm))

        override def encrypt[A <: CipherAlgorithm](
            key: SecretKey[A],
            iv: IvParameterSpec[A],
            data: ByteVector): F[ByteVector] =
          key match {
            case SecretKeySpec(key, algorithm) =>
              for {
                key <- F.fromPromise(
                  F.delay(
                    crypto
                      .subtle
                      .importKey(
                        "raw",
                        key.toUint8Array,
                        AesImportParams(algorithm),
                        false,
                        js.Array("encrypt"))))
                cipherText <- F.fromPromise(
                  F.delay(
                    crypto
                      .subtle
                      .encrypt(Algorithm.toWebCrypto(iv), key, data.toUint8Array.buffer)))
              } yield ByteVector.view(cipherText)
            case _ => F.raiseError(new InvalidKeyException)
          }

        override def decrypt[A <: CipherAlgorithm](
            key: SecretKey[A],
            iv: IvParameterSpec[A],
            data: ByteVector): F[ByteVector] =
          key match {
            case SecretKeySpec(key, algorithm) =>
              for {
                key <- F.fromPromise(
                  F.delay(
                    crypto
                      .subtle
                      .importKey(
                        "raw",
                        key.toUint8Array,
                        AesImportParams(algorithm),
                        false,
                        js.Array("decrypt"))))
                cipherText <- F.fromPromise(
                  F.delay(
                    crypto
                      .subtle
                      .decrypt(Algorithm.toWebCrypto(iv), key, data.toUint8Array.buffer)))
              } yield ByteVector.view(cipherText)
            case _ => F.raiseError(new InvalidKeyException)
          }

      }
  }
}
