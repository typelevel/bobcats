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

import cats.effect.kernel.{Async, Sync}
import scodec.bits.ByteVector
import cats.effect.std.SecureRandom
import cats.syntax.all._
import java.security.Provider
import javax.crypto.spec.{GCMParameterSpec, IvParameterSpec}
import javax.crypto
import java.nio.ByteBuffer

private final class JavaSecurityCipher[F[_]](providers: Providers)(implicit F: Sync[F])
    extends UnsealedCipher[F] {

  import BlockCipherAlgorithm._

  // TODO: What to do...
  private def aesCipherName(
      keyLength: AES.KeyLength,
      mode: BlockCipherMode,
      padding: Boolean): String =
    s"AES_${keyLength.toInt.toString}/${mode.toStringUppercase}/" + (if (padding) "PKCS5Padding"
                                                                     else "NoPadding")

  def importKey[A <: CipherAlgorithm[_]](key: ByteVector, algorithm: A): F[SecretKey[A]] =
    F.pure(SecretKeySpec(key, algorithm))

  private def oneshot[P <: CipherParams, A <: CipherAlgorithm[P]](
    mode: Int,
    key: SecretKey[A],
    params: P,
    data: ByteVector): F[ByteVector] = {

    F.catchNonFatal {
      val (cipher, out) = (key.algorithm, params) match {
        case (cbc: AES.CBC, AES.CBC.Params(iv)) =>
          val name = aesCipherName(cbc.keyLength, BlockCipherMode.CBC, false)
          val provider = providers.cipher(name) match {
            case Left(e) => throw e
            case Right(p) => p
          }
          val cipher = crypto.Cipher.getInstance(name, provider)
          cipher.init(
            mode,
            key.toJava,
            new IvParameterSpec(iv.data.toArray))
          // TODO: Calculate length properly
          val len = data.length.toInt
          (cipher, ByteBuffer.allocate(len))
        case (gcm: AES.GCM, AES.GCM.Params(iv, tagLength, ad)) =>
          val name = aesCipherName(gcm.keyLength, BlockCipherMode.GCM, false)
          val provider = providers.cipher(name) match {
            case Left(e) => throw e
            case Right(p) => p
          }
          val cipher = crypto.Cipher.getInstance(name, provider)
          cipher.init(
            mode,
            key.toJava,
            new GCMParameterSpec(tagLength.value, iv.data.toArray))

          ad.foreach { data => cipher.updateAAD(data.toByteBuffer) }
          val len = data.length.toInt + tagLength.byteLength
          (cipher, ByteBuffer.allocate(len))
      }
      cipher.doFinal(data.toByteBuffer, out)
      out.rewind()
      val bv = ByteVector.view(out)
      bv
    }
  }


  override def encrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
    key: SecretKey[A],
    params: P,
    data: ByteVector): F[ByteVector] = 
    oneshot(crypto.Cipher.ENCRYPT_MODE, key, params, data)

  override def decrypt[P <: CipherParams, A <: CipherAlgorithm[P]](
    key: SecretKey[A],
    params: P,
    data: ByteVector): F[ByteVector] = 
    oneshot(crypto.Cipher.DECRYPT_MODE, key, params, data)
}

private[bobcats] trait CipherPlatform[F[_]] {
  // def importJavaKey(key: crypto.SecretKey): F[SecretKey[CipherAlgorithm]]
}

private[bobcats] trait CipherCompanionPlatform {

  private[bobcats] def forProviders[F[_]](providers: Providers)(
      implicit F: Sync[F]): Cipher[F] = {
    new JavaSecurityCipher(providers)
  }
}
