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

import cats.effect.kernel.Sync
import scodec.bits.ByteVector

import java.security

private[bobcats] trait VerifierPlatform[F[_]]

private[bobcats] trait VerifierCompanionPlatform {

  implicit def forSync[F[_]](implicit F: Sync[F]): Verifier[F] =
    new UnsealedVerifier[F] {
      override def verify(
          spec: SPKIKeySpec[_],
          sigType: AsymmetricKeyAlg.Signature
      ): F[(SigningString, Signature) => F[Boolean]] =
        // todo: if one is to catchNonFatal one should have exceptions that
        //   are consistent across JS and Java implementations (should one?)
        F.catchNonFatal {
          val pubKey: security.PublicKey = spec.toJava

          (signingStr: ByteVector, signature: ByteVector) => F.catchNonFatal {
            val sig: java.security.Signature = sigType.toJava
            sig.initVerify(pubKey)
            sig.update(signingStr.toByteBuffer)
            sig.verify(signature.toArray)
          }
        }
    }
}
